const axios = require('axios');

async function load(url) {
  const response = await axios.get(url, { timeout: 5000 });
  return response.someInternalField;
}
