
self.onmessage = async (event) => {
  const { salt, difficulty, expires } = event.data;

  let nonce = 0;
  //expire check
  while (true) {
    if (Date.now() > expires * 1000) {
      self.postMessage({ expired: true });
      return;
    }
    //hash salt and nonce and check leading 0 bits
    const hash = await sha256(salt + nonce);
    if (leadingZeroBits(hash) >= difficulty) {
      self.postMessage({ nonce: nonce });
      return;
    }
    nonce++;
  }
};

// SHA-256 of a text
async function sha256(text) {
  const bytes = new TextEncoder().encode(text);//turn into bytes
  const hash = await crypto.subtle.digest("SHA-256", bytes);//turn into hash
  return new Uint8Array(hash);//
}

// count how many 0 bits the hash starts with
function leadingZeroBits(bytes) {
  let count = 0;
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit--) {
      if ((byte >> bit) & 1) return count; // found a 1, stop
      count++;
    }
  }
  return count;
}