import { getApiBaseUrl } from "@/lib/utils/port";
import { getWebSocketUrl } from "@/lib/utils/port";
import { isLoggingOut } from "@/lib/utils/logoutState";
import React, { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

type MessageHandler = (data: any) => void;

interface WebSocketContextType {
	isConnected: boolean;
	ws: React.RefObject<WebSocket | null>;
	subscribe: (channel: string, handler: MessageHandler) => () => void;
	send: (data: any) => void;
}

const WebSocketContext = createContext<WebSocketContextType | null>(null);

interface WebSocketProviderProps {
	children: ReactNode;
	path?: string;
}

// The socket outlives any single provider mount so a shell re-render does not
// tear the connection down. All reconnect bookkeeping lives here too, rather
// than in refs, so a close event that fires after the provider unmounted can
// still be reasoned about: it consults this state instead of a stale closure.
let globalWsRef: WebSocket | null = null;
const messageHandlers = new Map<string, Set<MessageHandler>>();
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let retryCount = 0;
// Set to false once auth is gone (logout, or the ticket endpoint answering
// 401/403). Nothing reconnects until the next provider mount re-enables it.
let reconnectEnabled = true;
// The connect function of the currently mounted provider, or null. A close
// event schedules a reconnect only through this, never through the closure
// that created the socket.
let activeConnect: (() => void) | null = null;

const clearReconnectTimer = () => {
	if (reconnectTimer) {
		clearTimeout(reconnectTimer);
		reconnectTimer = null;
	}
};

const scheduleReconnect = () => {
	if (!reconnectEnabled || !activeConnect || reconnectTimer) {
		return;
	}
	// Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s (max)
	retryCount = Math.min(retryCount + 1, 6);
	const delay = Math.pow(2, retryCount) * 500;
	reconnectTimer = setTimeout(() => {
		reconnectTimer = null;
		activeConnect?.();
	}, delay);
};

/**
 * Tears down the shared websocket and disables reconnection. Called on
 * sign-out so the client stops requesting tickets for a session that no
 * longer exists. The next WebSocketProvider mount (i.e. the next login)
 * re-enables reconnection.
 */
export function stopWebSocket() {
	reconnectEnabled = false;
	clearReconnectTimer();
	const ws = globalWsRef;
	globalWsRef = null;
	if (ws) {
		// Detach first so the close event does not try to reconnect.
		ws.onclose = null;
		ws.onerror = null;
		try {
			ws.close();
		} catch {
			// Already closed.
		}
	}
}

export function WebSocketProvider({ children, path = "/ws" }: WebSocketProviderProps) {
	const wsRef = useRef<WebSocket | null>(globalWsRef);
	const pingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
	const [isConnected, setIsConnected] = useState(globalWsRef?.readyState === WebSocket.OPEN);

	const subscribe = useCallback<(channel: string, handler: MessageHandler) => () => void>((channel, handler) => {
		if (!messageHandlers.has(channel)) {
			messageHandlers.set(channel, new Set());
		}
		messageHandlers.get(channel)!.add(handler);

		// Return unsubscribe function
		return () => {
			const handlers = messageHandlers.get(channel);
			if (handlers) {
				handlers.delete(handler);
				if (handlers.size === 0) {
					messageHandlers.delete(channel);
				}
			}
		};
	}, []);

	const send = (data: any) => {
		if (wsRef.current?.readyState === WebSocket.OPEN) {
			try {
				wsRef.current.send(typeof data === "string" ? data : JSON.stringify(data));
			} catch (error) {
				console.error("Error sending message:", error);
			}
		}
	};

	useEffect(() => {
		let mounted = true;

		const stopPing = () => {
			if (pingTimerRef.current) {
				clearInterval(pingTimerRef.current);
				pingTimerRef.current = null;
			}
		};

		const connect = async () => {
			if (!mounted || !reconnectEnabled || isLoggingOut()) {
				return;
			}
			if (globalWsRef?.readyState === WebSocket.OPEN || globalWsRef?.readyState === WebSocket.CONNECTING) {
				wsRef.current = globalWsRef;
				return;
			}

			const wsUrl = getWebSocketUrl(path);
			// Obtain a short-lived, single-use ticket for WS auth instead of putting the session token in the URL.
			let wsUrlWithAuth = wsUrl;
			try {
				const resp = await fetch(`${getApiBaseUrl()}/session/ws-ticket`, {
					method: "POST",
					credentials: "include",
				});
				if (resp.status === 401 || resp.status === 403) {
					// The session is gone. Retrying cannot succeed until the user
					// signs in again, at which point the dashboard shell remounts
					// this provider and re-enables reconnection.
					reconnectEnabled = false;
					if (mounted) setIsConnected(false);
					return;
				}
				if (resp.ok) {
					const { ticket } = await resp.json();
					if (ticket) {
						const parsed = new URL(wsUrl);
						parsed.searchParams.set("ticket", ticket);
						wsUrlWithAuth = parsed.toString();
					}
				}
			} catch {
				// If ticket fetch fails, attempt connection without auth param (cookie fallback)
			}
			// The ticket fetch is async; the provider may have unmounted or a
			// logout may have started while it was in flight.
			if (!mounted || !reconnectEnabled || isLoggingOut()) {
				return;
			}
			const ws = new WebSocket(wsUrlWithAuth);
			wsRef.current = ws;
			globalWsRef = ws;

			ws.onopen = () => {
				if (globalWsRef !== ws) return;
				if (mounted) setIsConnected(true);
				retryCount = 0; // Reset retry count on successful connection
				clearReconnectTimer();

				// Start heartbeat/ping to keep connection alive
				stopPing();
				pingTimerRef.current = setInterval(() => {
					if (ws.readyState === WebSocket.OPEN) {
						try {
							ws.send("ping");
						} catch (error) {
							console.error("Error sending ping:", error);
						}
					}
				}, 25000); // Ping every 25 seconds
			};

			ws.onmessage = (event) => {
				try {
					const data = JSON.parse(event.data);
					const messageType = data.type || "default";

					// Notify all subscribers for this message type
					const handlers = messageHandlers.get(messageType);
					if (handlers) {
						handlers.forEach((handler) => handler(data));
					}

					// Also notify wildcard subscribers
					const wildcardHandlers = messageHandlers.get("*");
					if (wildcardHandlers) {
						wildcardHandlers.forEach((handler) => handler(data));
					}
				} catch (error) {
					console.error("Error parsing message:", error);
				}
			};

			ws.onclose = () => {
				if (mounted) setIsConnected(false);
				stopPing();
				if (globalWsRef === ws) {
					globalWsRef = null;
				}
				// Reconnect through the currently mounted provider (if any), not
				// through this closure, so an unmounted provider never revives
				// the loop.
				scheduleReconnect();
			};

			ws.onerror = () => {
				if (mounted) setIsConnected(false);
				ws.close();
			};
		};

		// A fresh mount of the dashboard shell means the user is signed in:
		// re-arm reconnection that a previous logout switched off.
		reconnectEnabled = true;
		activeConnect = () => {
			void connect();
		};
		void connect();

		// Cleanup function
		return () => {
			mounted = false;
			// Don't close the WebSocket on unmount since it's global, but make
			// sure nothing reconnects on behalf of this provider once it is gone.
			activeConnect = null;
			clearReconnectTimer();
			stopPing();
		};
	}, [path]);

	return <WebSocketContext.Provider value={{ isConnected, ws: wsRef, subscribe, send }}>{children}</WebSocketContext.Provider>;
}

export function useWebSocket() {
	const context = useContext(WebSocketContext);
	if (!context) {
		throw new Error("useWebSocket must be used within a WebSocketProvider");
	}
	return context;
}