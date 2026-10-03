import { writable } from 'svelte/store';

export const activeClients = writable<number>(0);
