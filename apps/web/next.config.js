/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: "/api/backend/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"}/api/v1/:path*`,
      },
    ];
  },
  async redirects() {
    return [
      {
        source: "/videos",
        destination: "/",
        permanent: false,
      },
      {
        source: "/videos/:path*",
        destination: "/",
        permanent: false,
      },
    ];
  },
};

module.exports = nextConfig;
