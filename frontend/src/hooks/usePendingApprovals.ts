"use client";

import { useState, useEffect, useCallback } from 'react';

export type PendingApproval = {
    request_id: string;
    kind: string;
    created_at: number;
    expires_at: number;
    confirm_token?: string;
};

export function usePendingApprovals() {
    const [approvals, setApprovals] = useState<PendingApproval[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchApprovals = useCallback(async () => {
        try {
            const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
            const res = await fetch(`${apiUrl}/api/pending-approvals`);
            const data = await res.json();
            setApprovals(data.pending || []);
        } catch (err) {
            console.error('Failed to fetch approvals:', err);
        } finally {
            setLoading(false);
        }
    }, []);

    const handleApproval = async (requestId: string, token: string, approve: boolean) => {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
        const res = await fetch(`${apiUrl}/api/approve-trade`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                request_id: requestId,
                confirm_token: token,
                approve
            })
        });

        if (res.ok) {
            fetchApprovals();
            return true;
        }
        return false;
    };

    useEffect(() => {
        fetchApprovals();
        const interval = setInterval(fetchApprovals, 10000);
        return () => clearInterval(interval);
    }, [fetchApprovals]);

    return { approvals, loading, fetchApprovals, handleApproval };
}
