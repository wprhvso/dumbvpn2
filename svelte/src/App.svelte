<script lang="ts">
  import StatusMatrix from './lib/components/StatusMatrix.svelte';
  import ClientManager from './lib/components/ClientManager.svelte';
  import LogViewer from './lib/components/LogViewer.svelte';
</script>

<main class="container mx-auto p-4 space-y-6">
  <h1 class="text-2xl font-bold">Mesh Proxy Controller</h1>
  <StatusMatrix />
  <ClientManager />
  <LogViewer />
</main>
