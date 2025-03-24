const fs = require('fs');
const scryptMcf = require('scrypt-mcf');

async function createUsers() {
  const fast_users = [
    { username: 'walrus', password: 'walrus_1' },
    { username: 'jruiz', password: 'jruiz' },
    { username: 'sruiz', password: '1234' }
  ];
  const slow_users = [
    { username: 'walrus', password: 'walrus_2' },
    { username: 'jruiz', password: '1234' },
    { username: 'sruiz', password: 'sruiz' }
  ];


  const fastKdfOptions = {
    derivedKeyLength: 64,
    scryptParams: { logN: 12, r: 8, p: 1 }
  };


  const slowKdfOptions = {
    derivedKeyLength: 64,
    scryptParams: { logN: 20, r: 8, p: 2 }
  };

  const fastHashedUsers = await Promise.all(fast_users.map(async (user) => {
    const hashedPassword = await scryptMcf.hash(user.password, fastKdfOptions);
    return { username: user.username, password: hashedPassword};
  }));

  const slowHashedUsers = await Promise.all(slow_users.map(async (user) => {
    const hashedPassword = await scryptMcf.hash(user.password, slowKdfOptions);
    return { username: user.username, password: hashedPassword};
  }));


  fs.writeFileSync('users_fast.json', JSON.stringify(fastHashedUsers, null, 2));
  console.log('Fast credentials created and saved to users_fast.json');
  fs.writeFileSync('users_slow.json', JSON.stringify(slowHashedUsers, null, 2));
  console.log('Slow credentials created and saved to users_slow.json');
}

createUsers().catch(console.error);
