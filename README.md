# User Details API

This project creates a **Node.js** application that exposes a **GET API** to collect various user details such as:

- **IP Address**
- **User-Agent** (Browser/OS)
- **Geolocation** (Country, Region, City)
- **Referrer URL** (Where the request is coming from)
- **Headers**
- **Query Parameters** (GET parameters)

## Packages Used

This project uses the following packages to collect user data:

1. **express**: A web framework for Node.js.
2. **useragent**: Parses the `User-Agent` header to extract information about the browser, platform, and device.
3. **geoip-lite**: Provides geolocation information based on the user's IP address.
4. **request-ip**: A simple package to retrieve the IP address of the client making the request.
5. **axios**: Makes HTTP requests to send collected data to an external API (optional).
6. **dotenv**: Loads environment variables from a `.env` file.

## Installation

Follow these steps to set up and run the project locally:

### 1. Clone the Repository

```bash
git clone https://github.com/Nikhil012N/ip-tracker.git
cd ip-tracker
