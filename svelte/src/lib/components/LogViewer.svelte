<script lang="ts">
  import { logs } from '../stores/live_logs';
</script>

<div class="bg-black text-green-400 p-4 font-mono h-64 overflow-y-auto">
  {#each $logs as log}
    <div>{log}</div>
  {/each}
</div>
