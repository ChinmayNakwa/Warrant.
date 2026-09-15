import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Pins the workspace root to this directory - without it Turbopack walks up
  // and picks up an unrelated package-lock.json in the user's home directory.
  turbopack: {
    root: path.resolve(__dirname),
  },
  // The default bottom-left indicator sits on top of the sidebar's "Log out"
  // button in dev and swallows its clicks.
  devIndicators: {
    position: "bottom-right",
  },
  // Stops `next dev` writing its own guidance files into this directory.
  agentRules: false,
};

export default nextConfig;
