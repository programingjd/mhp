const url=new URL('pow.wasm',import.meta.url);
await (await fetch(url)).arrayBuffer();
const worker=()=>new Promise(r=>{
  const worker=new Worker(new URL('./pow_worker_script.mjs',import.meta.url),{type: 'module'});
  worker.onmessage=msg=>{
    if(msg.data==='ready')
      worker.onmessage=null;
    r(worker);
  };
});
let [worker1,worker2]=await Promise.all([worker(),worker()]);
const generate=async(nonce)=>{
  let w1=worker1;
  let w2=worker2;
  worker1=worker2=null;
  if(!w1){
    w1= await worker();
    w2= await worker();
  }
  let chain1=new Promise(r=>{
    w1.onmessage=({data})=>{
      w1.onmessage=null;
      w1.terminate();
      r(data);
    };
    w1.postMessage({nonce_for_chain1: nonce});
  });
  let chain2=new Promise(r=>{
    w2.onmessage=({data})=>{
      w2.onmessage=null;
      r(data);
    };
    w2.postMessage({nonce_for_chain2: nonce});
  });
  [chain1,chain2]= await Promise.all([chain1,chain2]);
  return await new Promise(r=>{
    w2.onmessage=({data})=>{
      w2.onmessage=null;
      w2.terminate();
      r(data);
    }
    w2.postMessage({chain1,chain2},[chain1.buffer,chain2.buffer]);
  });
};
export {generate};
export default generate;
