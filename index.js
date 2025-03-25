
const express = require('express');
const useragent = require('useragent');
const geoip = require('geoip-lite');
const requestIp = require('request-ip');
const axios = require('axios');
require('dotenv').config();

const app = express();
const port = 3000;

// Middleware to handle JSON requests
app.use(express.json());

app.get('/', async (req, res) => {
  const clientIp = requestIp.getClientIp(req);
  const agent = useragent.parse(req.headers['user-agent']);
  const geo = geoip.lookup(clientIp);
  const referrer = req.headers.referer || req.headers.referrer;
  const headers = req.headers;
  const queryParams = req.query;
  const userDetails = {
    ipAddress: clientIp,
    userAgent: agent,
    geoLocation: geo,
    referrer,
    headers,
    queryParams,
  };

  res.json(userDetails);
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
