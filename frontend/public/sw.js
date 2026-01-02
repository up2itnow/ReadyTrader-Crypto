// ReadyTrader-Crypto Service Worker for PWA
// Provides offline support and push notifications for trade approvals

const CACHE_NAME = 'readytrader-v1';
const STATIC_ASSETS = [
  '/',
  '/manifest.json',
  '/globals.css',
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch event - network first, fall back to cache
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;
  
  // Skip API requests (always fetch from network)
  if (event.request.url.includes('/api/')) return;
  
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Clone the response before caching
        const responseClone = response.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseClone);
        });
        return response;
      })
      .catch(() => {
        // Fall back to cache if network fails
        return caches.match(event.request);
      })
  );
});

// Push notification handler
self.addEventListener('push', (event) => {
  const options = {
    icon: '/icons/icon-192x192.png',
    badge: '/icons/badge-72x72.png',
    vibrate: [100, 50, 100],
    requireInteraction: true,
    actions: [
      { action: 'approve', title: '✓ Approve', icon: '/icons/approve.png' },
      { action: 'reject', title: '✗ Reject', icon: '/icons/reject.png' },
      { action: 'view', title: 'View Details', icon: '/icons/view.png' },
    ],
  };

  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: 'Trade Approval Required', body: event.data?.text() || 'New trade pending' };
  }

  const title = data.title || 'ReadyTrader Alert';
  const body = data.body || 'Action required';
  
  event.waitUntil(
    self.registration.showNotification(title, {
      ...options,
      body,
      data: data,
      tag: data.request_id || 'readytrader-notification',
    })
  );
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  const data = event.notification.data || {};
  const requestId = data.request_id;
  const confirmToken = data.confirm_token;
  
  if (event.action === 'approve' && requestId && confirmToken) {
    // Quick approve action
    event.waitUntil(
      handleApproval(requestId, confirmToken, true)
    );
  } else if (event.action === 'reject' && requestId && confirmToken) {
    // Quick reject action
    event.waitUntil(
      handleApproval(requestId, confirmToken, false)
    );
  } else {
    // Default: open the app
    event.waitUntil(
      clients.matchAll({ type: 'window' }).then((clientList) => {
        // If app is already open, focus it
        for (const client of clientList) {
          if (client.url.includes('/') && 'focus' in client) {
            return client.focus();
          }
        }
        // Otherwise, open new window
        if (clients.openWindow) {
          const url = requestId ? `/approvals?id=${requestId}` : '/approvals';
          return clients.openWindow(url);
        }
      })
    );
  }
});

// Handle approval/rejection from notification
async function handleApproval(requestId, confirmToken, approve) {
  const apiUrl = self.registration.scope.replace(/\/$/, '');
  
  try {
    const response = await fetch(`${apiUrl}/api/approve-trade`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        request_id: requestId,
        confirm_token: confirmToken,
        approve: approve,
      }),
    });
    
    const result = await response.json();
    
    // Show result notification
    await self.registration.showNotification(
      approve ? 'Trade Approved' : 'Trade Rejected',
      {
        body: result.ok 
          ? `Trade ${approve ? 'approved' : 'rejected'} successfully`
          : `Error: ${result.error?.message || 'Unknown error'}`,
        icon: '/icons/icon-192x192.png',
        tag: 'approval-result',
      }
    );
    
    // Notify all open clients to refresh
    const allClients = await clients.matchAll({ type: 'window' });
    for (const client of allClients) {
      client.postMessage({
        type: 'APPROVAL_PROCESSED',
        requestId,
        approve,
        result,
      });
    }
  } catch (error) {
    await self.registration.showNotification('Error', {
      body: `Failed to ${approve ? 'approve' : 'reject'} trade: ${error.message}`,
      icon: '/icons/icon-192x192.png',
      tag: 'approval-error',
    });
  }
}

// Background sync for offline approvals
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-approvals') {
    event.waitUntil(syncPendingApprovals());
  }
});

async function syncPendingApprovals() {
  // Get pending approvals from IndexedDB and process them
  // This allows approvals to be queued when offline
  console.log('Syncing pending approvals...');
}

// Periodic background sync for checking new approvals
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'check-approvals') {
    event.waitUntil(checkForNewApprovals());
  }
});

async function checkForNewApprovals() {
  try {
    const apiUrl = self.registration.scope.replace(/\/$/, '');
    const response = await fetch(`${apiUrl}/api/pending-approvals`);
    const data = await response.json();
    
    const pending = data.pending || [];
    if (pending.length > 0) {
      // Show notification for pending approvals
      await self.registration.showNotification('Pending Approvals', {
        body: `${pending.length} trade${pending.length > 1 ? 's' : ''} awaiting approval`,
        icon: '/icons/icon-192x192.png',
        badge: '/icons/badge-72x72.png',
        tag: 'pending-check',
        data: { pending },
      });
    }
  } catch (error) {
    console.error('Failed to check approvals:', error);
  }
}
