<script lang="ts">
  import { nodes } from '../stores/nodes';
</script>

<div class="grid grid-cols-2 gap-4">
  {#each $nodes as node}
    <div class="p-4 border rounded shadow">
      <div class="font-bold">{node.name}</div>
      <div>{node.virtual_ip} - {node.rtt_ms}ms</div>
    </div>
  {/each}
</div>
