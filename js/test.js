var nacl = (typeof window !== 'undefined') ? window.nacl : require('./' + (process.env.NACL_SRC || 'cryptobox.js'));


var enc = nacl.util.encodeBase64,
    dec = nacl.util.decodeBase64;

var pk1 = new Uint8Array(32),
    sk1 = new Uint8Array(32),
    pk2 = new Uint8Array(32),
    sk2 = new Uint8Array(32),
    key= new Uint8Array(32),
    iterations = 1000,    // Number of iterations for fuzz testing 
    nonce = new Uint8Array(24);
console.log("\n \t Test - Rspamd JS Cryptobox: \n");

/*
    8 bytes of Random data 
*/

var data = new Uint8Array(8);
data = nacl.randomBytes(8);
keypair=nacl.box.keyPair();
pk1 = keypair['publicKey'];
sk1 = keypair['secretKey'];
// console.log(pk1);
// console.log(sk1);
keypair=nacl.box.keyPair();
pk2 = keypair['publicKey'];
sk2 = keypair['secretKey'];
// console.log(pk2);
// console.log(sk2);
nonce = nacl.randomBytes(24);
var ctx = new Uint8Array(data.length + 16);

ctx = nacl.box(data,nonce,pk2,sk1);

var pt = new Uint8Array(ctx.length - 16);
pt = nacl.box.open(ctx,nonce,pk1,sk2);
if(pt===false)
  console.log(" Baseline Encryption Test (8 Bytes random msg): FAILED\n")
else
  console.log(" Baseline Encryption Test (8 Bytes random msg):  PASSED\n");
/*
    Cipher Text Manipulated Test 
*/

ctx[3]=0;

pt= nacl.box.open(ctx,nonce,pk1,sk2);

if( pt === false)
  console.log(" CTX Manipulated Test : PASSED \n");
else
  console.log(" CTX Manipulated Test : FAILED");

/*
    nonce Manipulated Test 
*/

nonce[3]=0;

pt= nacl.box.open(ctx,nonce,pk1,sk2);

if( pt === false)
  console.log(" Nonce Manipulated Test : PASSED\n");
else
  console.log(" Nonce Manipulated Test : FAILED");

/* 
    64 Bytes Ramdom Data
*/
data = new nacl.randomBytes(64);
ctx = new Uint8Array(data.length + 16);

ctx = nacl.box(data,nonce,pk2,sk1);

pt = new Uint8Array(ctx.length - 16);

pt = nacl.box.open(ctx,nonce,pk1,sk2);
if(pt===false)
  console.log(" Baseline Encryption Test (64 Bytes random msg): FAILED\n")
else
  console.log(" Baseline Encryption Test (64 Bytes random msg):  PASSED\n");

/*
    Cipher Text Manipulated Test 
*/
var rand = Math.floor(Math.random()*10);
ctx[rand]=0;

pt= nacl.box.open(ctx,nonce,pk1,sk2);

if( pt === false)
  console.log(" CTX Manipulated Test : PASSED \n");
else
  console.log(" CTX Manipulated Test : FAILED");

/*
    nonce Manipulated Test 
*/

nonce[rand]=0;

pt= nacl.box.open(ctx,nonce,pk1,sk2);

if( pt === false)
  console.log(" Nonce Manipulated Test : PASSED\n");
else
  console.log(" Nonce Manipulated Test : FAILED");
  
/*
    256 Bytes Random Data
*/
data = new nacl.randomBytes(256);
ctx = new Uint8Array(data.length + 16);

ctx = nacl.box(data,nonce,pk2,sk1);

pt = new Uint8Array(ctx.length - 16);

pt = nacl.box.open(ctx,nonce,pk1,sk2);
if(pt===false)
  console.log(" Baseline Encryption Test (256 Bytes random msg): FAILED\n")
else
  console.log(" Baseline Encryption Test (256 Bytes random msg):  PASSED\n");
/*
    Cipher Text Manipulated Test 
*/
rand = Math.floor(Math.random()*100);

ctx[rand]=0;

pt= nacl.box.open(ctx,nonce,pk1,sk2);

if( pt === false)
  console.log(" CTX Manipulated Test : PASSED \n");
else
  console.log(" CTX Manipulated Test : FAILED");

/*
    nonce Manipulated Test 
*/

nonce[rand]=0;

pt= nacl.box.open(ctx,nonce,pk1,sk2);

if( pt === false)
  console.log(" Nonce Manipulated Test : PASSED\n");
else
  console.log(" Nonce Manipulated Test : FAILED");

/* 
    Fuzzy test for small random <100 Bytes of data 
*/
var len;
var t1,t2,t3=0,t4=0;
for(var i =0 ; i < iterations ; i++)
{
  len = Math.floor(Math.random()*100);
  data = new nacl.randomBytes(len);
  ctx = new Uint8Array(data.length + 16);
  t1= Date.now();
  ctx = nacl.box(data,nonce,pk2,sk1);
  t2= Date.now();
  t3+=t2-t1;
  t4+=t2-t1;
  pt = new Uint8Array(ctx.length - 16);
  // if(i == 43201)
  //   nonce[20]=0;
  pt = nacl.box.open(ctx,nonce,pk1,sk2);
  
  if(pt===false)
  {
    console.log("Iteration %d. Random Fuzz Test (%d Bytes random msg): FAILED\n",i,len);
    break;
  }

  if( i% (iterations/10) == 0)
  {
    if(pt===false)
    {
      console.log("Iteration %d. Random Fuzz Test : FAILED\n",i,len);
      break;
    }
    else
    {
      if(i!=0)
        console.log("Iteration %d. Random Fuzz Test :  PASSED , AVG. Time :"+t4/(iterations/10)+"  ms\n",i );
      t4=0;
    }
  }
}
if(pt===false)
  console.log(" Fuzz Test FAILED at %d Bytes random message \n",len);
else
  console.log(" All Fuzz Tests with <100 Bytes random message: PASSED , AVG. Time :"+t3/iterations+"  ms\n");

/* Fuzzy test for large 100-1000 Bytes random message */
t3=0;
t4=0;
for(var i =0 ; i < iterations ; i++)
{
  len = Math.floor(Math.random()*1000+100);
  data = new nacl.randomBytes(len);
  ctx = new Uint8Array(data.length + 16);
  t1= Date.now();
  ctx = nacl.box(data,nonce,pk2,sk1);
  t2= Date.now();
  t3+=t2-t1;
  t4+=t2-t1;
  pt = new Uint8Array(ctx.length - 16);
  // if(i == 43201)
  //   nonce[20]=0;
  pt = nacl.box.open(ctx,nonce,pk1,sk2);
  
  if(pt===false)
  {
    console.log("Iteration %d. Random Fuzz Test (%d Bytes random msg): FAILED\n",i,len);
    break;
  }

  if( i% (iterations/10) == 0)
  {
    if(pt===false)
    {
      console.log("Iteration %d. Random Fuzz Test : FAILED\n",i,len);
      break;
    }
    else
    {
      if(i!=0)
        console.log("Iteration %d. Random Fuzz Test :  PASSED , AVG. Time :"+t4/(iterations/10)+"  ms\n",i );
      t4=0;
    }
  }
}
if(pt===false)
  console.log(" Fuzzy Test FAILED at %d Bytes random message \n",len);
else
  console.log(" All Fuzzy Tests with 100-1000 Bytes random message: PASSED , AVG. Time :"+t3/iterations+"  ms\n");

/* Fuzzy test for Very large 1000-10000 Bytes random message */
t3=0;
t4=0;
for(var i =0 ; i < iterations ; i++)
{
  len = Math.floor(Math.random()*100000+1000);
  data = new nacl.randomBytes(len);
  ctx = new Uint8Array(data.length + 16);
  t1= Date.now();
  ctx = nacl.box(data,nonce,pk2,sk1);
  t2= Date.now();
  t3+=t2-t1;
  t4+=t2-t1;
  pt = new Uint8Array(ctx.length - 16);
  /*if(i == 43)
    pk2[20]=0;
  */  
  pt = nacl.box.open(ctx,nonce,pk1,sk2);
  
  if(pt===false)
  {
    console.log("Iteration %d. Random Fuzz Test (%d Bytes random msg): FAILED\n",i,len);
    break;
  }

  if( i% (iterations/10) == 0)
  {
    if(pt===false)
    {
      console.log("Iteration %d. Random Fuzz Test : FAILED\n",i,len);
      break;
    }
    else
    {
      if(i!=0)
        console.log("Iteration %d. Random Fuzz Test :  PASSED , AVG. Time :"+t4/(iterations/10)+"  ms\n",i );
      t4=0;
    }
  }
}
if(pt===false)
  console.log(" Fuzzy Test FAILED at %d Bytes random message \n",len);
else
  console.log(" All Fuzzy Tests with 1000-100000 Bytes random message: PASSED , AVG. Time :"+t3/iterations+"  ms\n");