<script lang="ts">
  let clientName = '';
  function createClient() {
    clientName = '';
  }
</script>

<div>
  <input bind:value={clientName} placeholder="Client name" class="border p-2" />
  <button on:click={createClient} class="bg-blue-500 text-white p-2">Create</button>
</div>
