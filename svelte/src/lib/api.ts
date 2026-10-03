export interface PeerNode {
  id: string;
  name: string;
  virtual_ip: string;
  rtt_ms: number;
  online: boolean;
}

export async function fetchPeers(): Promise<PeerNode[]> {
  const res = await fetch('/api/v1/peers');
  return res.json();
}
