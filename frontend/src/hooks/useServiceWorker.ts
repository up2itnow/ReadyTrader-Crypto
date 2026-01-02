"use client";

import { useEffect, useState, useCallback, useMemo } from 'react';

// Check support outside of component to avoid effect issues
const checkSupport = () => {
  if (typeof window === 'undefined') return false;
  return 'serviceWorker' in navigator && 'PushManager' in window;
};

const getInitialPermission = (): NotificationPermission => {
  if (typeof window === 'undefined') return 'default';
  if ('Notification' in window) return Notification.permission;
  return 'default';
};

export function useServiceWorker() {
  // Use lazy initialization to avoid effect setState
  const isSupported = useMemo(() => checkSupport(), []);
  const [isRegistered, setIsRegistered] = useState(false);
  const [registration, setRegistration] = useState<ServiceWorkerRegistration | null>(null);
  const [subscription, setSubscription] = useState<PushSubscriptionJSON | null>(null);
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission>(getInitialPermission);

  // Register service worker
  useEffect(() => {
    if (!isSupported) return;

    const registerSW = async () => {
      try {
        const reg = await navigator.serviceWorker.register('/sw.js', {
          scope: '/',
        });
        
        setRegistration(reg);
        setIsRegistered(true);
        
        // Check for existing push subscription
        const existingSub = await reg.pushManager.getSubscription();
        if (existingSub) {
          setSubscription(existingSub.toJSON());
        }
        
        console.log('Service Worker registered:', reg.scope);
      } catch (error) {
        console.error('Service Worker registration failed:', error);
      }
    };

    registerSW();
  }, [isSupported]);

  // Listen for messages from service worker
  useEffect(() => {
    if (!isSupported) return;

    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'APPROVAL_PROCESSED') {
        // Dispatch custom event for components to handle
        window.dispatchEvent(new CustomEvent('approvalProcessed', {
          detail: event.data,
        }));
      }
    };

    navigator.serviceWorker.addEventListener('message', handleMessage);
    return () => {
      navigator.serviceWorker.removeEventListener('message', handleMessage);
    };
  }, [isSupported]);

  // Request notification permission
  const requestNotificationPermission = useCallback(async () => {
    if (!('Notification' in window)) {
      console.warn('Notifications not supported');
      return false;
    }

    try {
      const permission = await Notification.requestPermission();
      setNotificationPermission(permission);
      return permission === 'granted';
    } catch (error) {
      console.error('Failed to request notification permission:', error);
      return false;
    }
  }, []);

  // Subscribe to push notifications
  const subscribeToPush = useCallback(async () => {
    if (!registration) {
      console.warn('Service worker not registered');
      return null;
    }

    if (notificationPermission !== 'granted') {
      const granted = await requestNotificationPermission();
      if (!granted) {
        console.warn('Notification permission denied');
        return null;
      }
    }

    try {
      // Get VAPID public key from server
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/push/vapid-public-key`);
      
      if (!response.ok) {
        // If server doesn't support push, use local notifications only
        console.log('Push notifications not configured on server, using local notifications');
        return null;
      }
      
      const { publicKey } = await response.json();
      
      const sub = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey),
      });

      setSubscription(sub.toJSON());

      // Send subscription to server
      await fetch(`${apiUrl}/api/push/subscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sub.toJSON()),
      });

      return sub;
    } catch (error) {
      console.error('Failed to subscribe to push:', error);
      return null;
    }
  }, [registration, notificationPermission, requestNotificationPermission]);

  // Unsubscribe from push notifications
  const unsubscribeFromPush = useCallback(async () => {
    if (!registration) return false;

    try {
      const sub = await registration.pushManager.getSubscription();
      if (sub) {
        await sub.unsubscribe();
        setSubscription(null);
        
        // Notify server
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
        await fetch(`${apiUrl}/api/push/unsubscribe`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ endpoint: sub.endpoint }),
        });
      }
      return true;
    } catch (error) {
      console.error('Failed to unsubscribe from push:', error);
      return false;
    }
  }, [registration]);

  // Show local notification (for testing or fallback)
  const showLocalNotification = useCallback(async (title: string, options?: NotificationOptions) => {
    if (notificationPermission !== 'granted') {
      const granted = await requestNotificationPermission();
      if (!granted) return;
    }

    if (registration) {
      await registration.showNotification(title, {
        icon: '/icons/icon-192x192.png',
        badge: '/icons/badge-72x72.png',
        ...options,
      });
    }
  }, [registration, notificationPermission, requestNotificationPermission]);

  return {
    isSupported,
    isRegistered,
    registration,
    subscription,
    notificationPermission,
    requestNotificationPermission,
    subscribeToPush,
    unsubscribeFromPush,
    showLocalNotification,
  };
}

// Helper function to convert VAPID key
function urlBase64ToUint8Array(base64String: string): ArrayBuffer {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray.buffer as ArrayBuffer;
}
