import { randomBytes, pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';

const password = process.argv[2];
if (!password) {
  console.error('Usage: npm run hash-password -- "YourPassword"');
  process.exit(1);
}
const iterations = 120000;
const salt = randomBytes(16);
const derive = promisify(pbkdf2);
const hash = await derive(password, salt, iterations, 32, 'sha256');
console.log(`pbkdf2_sha256$${iterations}$${salt.toString('base64url')}$${hash.toString('base64url')}`);
