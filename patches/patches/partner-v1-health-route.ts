// Existing sanitized PATCHES partner API starting point.
export const dynamic = "force-static";
export function GET() {
  return Response.json({
    service: "PATCHES Partner API",
    version: "v1",
    status: "available",
    directDatabaseAccess: false,
    requiresScopedAuthentication: true,
  });
}
