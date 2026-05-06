import { SenderAuthenticationKeyPair } from "@partisiablockchain/blockchain-api-transaction-client";

const input = await new Promise((resolve, reject) => {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
  });
  process.stdin.on("end", () => resolve(buf.trim()));
  process.stdin.on("error", reject);
});

if (!input) {
  throw new Error("sender key input required");
}

const auth = SenderAuthenticationKeyPair.fromString(input);
process.stdout.write(`${auth.getAddress()}\n`);
