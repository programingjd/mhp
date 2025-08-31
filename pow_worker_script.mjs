const url=new URL('pow.wasm',import.meta.url);
let wasm;
const wbg={
  __wbindgen_init_externref_table: function(){
    const table=wasm.__wbindgen_export_0;
    const offset=table.grow(4);
    table.set(0);
    table.set(offset);
    table.set(offset+1,null);
    table.set(offset+2,true);
    table.set(offset+3,false);
  }
};
const {instance}=await WebAssembly.instantiateStreaming(await fetch(url,{cache: 'force-cache'}),{wbg});
wasm=instance.exports;
const malloc=wasm.__wbindgen_malloc;
const free=wasm.__wbindgen_free;
const chain1=nonce=>{
  const p1=malloc(16,1);
  new Uint8Array(wasm.memory.buffer).set(nonce,p1);
  const [p2,n2]=wasm.generate_first_chain(p1,16);
  const res=new Uint8Array(wasm.memory.buffer).subarray(p2,p2+n2).slice();
  free(p2,n2);
  return res;
};
const chain2=nonce=>{
  const p1=malloc(16,1);
  new Uint8Array(wasm.memory.buffer).set(nonce,p1);
  const [p2,n2]=wasm.generate_second_chain(p1,16);
  const res=new Uint8Array(wasm.memory.buffer).subarray(p2,p2+n2).slice();
  free(p2,n2);
  return res;
};
const combine=(first_chain,second_chain)=>{
  const n1=first_chain.length;
  const p1=malloc(n1,1);
  new Uint8Array(wasm.memory.buffer).set(first_chain,p1);
  const n2=second_chain.length;
  const p2=malloc(n2,1);
  new Uint8Array(wasm.memory.buffer).set(second_chain,p2);
  const [p3,n3]=wasm.combine_chains(p1,n1,p2,n2);
  const res=new Uint8Array(wasm.memory.buffer).subarray(p3,p3+n3).slice();
  free(p3,n3);
  return res;
}
onmessage=({data})=>{
  const nonce_for_chain1=data.nonce_for_chain1;
  if(nonce_for_chain1){
    console.log('starting generation of chain1');
    const chain=chain1(nonce_for_chain1);
    console.log(`chain1 generated: ${chain.length} bytes`);
    return postMessage(chain,[chain.buffer]);
  }
  const nonce_for_chain2=data.nonce_for_chain2;
  if(nonce_for_chain2){
    console.log('starting generation of chain2');
    const chain=chain2(nonce_for_chain2);
    console.log(`chain2 generated: ${chain.length} bytes`);
    return postMessage(chain,[chain.buffer]);
  }
  console.log('combining chains');
  const proof=combine(data.chain1,data.chain2);
  console.log(`proof generated: ${proof.length} bytes`);
  return postMessage(proof,[proof.buffer]);
};
postMessage('ready');
export {chain1,chain2,combine};
