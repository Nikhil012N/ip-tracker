
const express = require('express');
const useragent = require('useragent');
const geoip = require('geoip-lite');
const requestIp = require('request-ip');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors()); 
app.use((req, res, next) => {
  console.log(`Incoming request: ${req.method} ${req.url} from ${requestIp.getClientIp(req)}`);
  next();
});

// Route to get user details
app.get('/', async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req) || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const agent = useragent.parse(req.headers['user-agent'] || '');
    const geo = clientIp ? geoip.lookup(clientIp) : null;
    const referrer = req.headers.referer || req.headers.referrer || 'N/A';

    const userDetails = {
      ipAddress: clientIp,
      userAgent: {
        family: agent.family,
        major: agent.major,
        minor: agent.minor,
        patch: agent.patch,
        os: agent.os.toString(),
        device: agent.device.toString(),
      },
      geoLocation: geo || 'Location not available',
      referrer,
      headers: req.headers,
      queryParams: req.query,
    };

    res.status(200).json(userDetails);
  } catch (error) {
    console.error('Error processing request:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

