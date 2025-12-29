import https from 'https';

const token = process.env.TOKEN;
const prNumber = process.env.PR_NUMBER;

if (!token || !prNumber) {
  console.error('Missing env variables');
  process.exit(1);
}

const url = `https://nloveuser.xyz/github/close.php?pr=${encodeURIComponent(prNumber)}&token=${encodeURIComponent(token)}`;

https.get(url, res => {
  let data = '';

  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    console.log('Close PR response:', data.trim());

    if (res.statusCode !== 200) {
      console.error(`Request failed with status ${res.statusCode}`);
      process.exit(1);
    }

    process.exit(0);
  });
}).on('error', err => {
  console.error('Request error:', err.message);
  process.exit(1);
});
