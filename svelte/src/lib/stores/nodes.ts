import { writable } from 'svelte/store';
import type { PeerNode } from '../api';

export const nodes = writable<PeerNode[]>([]);
