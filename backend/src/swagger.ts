export const swaggerSpec = {
  openapi: "3.0.0",
  info: {
    title: "URL Shortener API",
    version: "1.0.0",
    description: "Shorten URLs, manage them, and track clicks.",
  },
  servers: [{ url: "http://localhost:3000" }],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
    schemas: {
      Url: {
        type: "object",
        properties: {
          id: { type: "integer", example: 6 },
          shortCode: { type: "string", example: "E3iW1x" },
          longUrl: { type: "string", example: "https://github.com" },
          clicks: { type: "integer", example: 42 },
          createdAt: { type: "string", format: "date-time" },
          userId: { type: "integer", nullable: true },
        },
      },
      Error: {
        type: "object",
        properties: { error: { type: "string", example: "description of what went wrong" } },
      },
    },
  },
  paths: {
    "/api/auth/register": {
      post: {
        summary: "Register a new user",
        tags: ["Auth"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["email", "password"],
                properties: {
                  email: { type: "string", example: "me@example.com" },
                  password: { type: "string", example: "atleast8chars" },
                },
              },
            },
          },
        },
        responses: {
          "201": { description: "User created" },
          "400": { description: "Missing/invalid fields" },
          "409": { description: "Email already registered" },
          "429": { description: "Rate limited" },
        },
      },
    },
    "/api/auth/login": {
      post: {
        summary: "Login — returns access + refresh tokens",
        tags: ["Auth"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["email", "password"],
                properties: {
                  email: { type: "string" },
                  password: { type: "string" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Tokens issued: { accessToken, refreshToken }" },
          "401": { description: "Invalid credentials" },
          "429": { description: "Rate limited" },
        },
      },
    },
    "/api/auth/refresh": {
      post: {
        summary: "Exchange a refresh token for a new token pair (rotates)",
        tags: ["Auth"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["refreshToken"],
                properties: { refreshToken: { type: "string" } },
              },
            },
          },
        },
        responses: {
          "200": { description: "New token pair" },
          "401": { description: "Invalid or expired refresh token" },
        },
      },
    },
    "/api/auth/logout": {
      post: {
        summary: "Revoke a refresh token (server-side logout)",
        tags: ["Auth"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["refreshToken"],
                properties: { refreshToken: { type: "string" } },
              },
            },
          },
        },
        responses: { "204": { description: "Logged out" } },
      },
    },
    "/api/urls": {
      get: {
        summary: "List my URLs (paginated, searchable)",
        tags: ["URLs"],
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: "page", in: "query", schema: { type: "integer", default: 1 } },
          { name: "limit", in: "query", schema: { type: "integer", default: 10, maximum: 50 } },
          { name: "search", in: "query", schema: { type: "string" } },
        ],
        responses: {
          "200": { description: "Paginated list: { data: Url[], pagination }" },
          "401": { description: "Not authenticated" },
        },
      },
      post: {
        summary: "Create a short URL",
        tags: ["URLs"],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["longUrl"],
                properties: { longUrl: { type: "string", example: "https://github.com" } },
              },
            },
          },
        },
        responses: {
          "201": { description: "Created", content: { "application/json": { schema: { $ref: "#/components/schemas/Url" } } } },
          "400": { description: "longUrl missing" },
          "401": { description: "Not authenticated" },
        },
      },
    },
    "/api/urls/{id}": {
      delete: {
        summary: "Delete one of my URLs",
        tags: ["URLs"],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: {
          "204": { description: "Deleted" },
          "403": { description: "Not the owner" },
          "404": { description: "Not found" },
        },
      },
      patch: {
        summary: "Edit one of my URLs' destination",
        tags: ["URLs"],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["longUrl"],
                properties: { longUrl: { type: "string" } },
              },
            },
          },
        },
        responses: {
          "200": { description: "Updated", content: { "application/json": { schema: { $ref: "#/components/schemas/Url" } } } },
          "403": { description: "Not the owner" },
          "404": { description: "Not found" },
        },
      },
    },
    "/{code}": {
      get: {
        summary: "Redirect a short code to its destination (public)",
        tags: ["Redirect"],
        parameters: [{ name: "code", in: "path", required: true, schema: { type: "string" } }],
        responses: {
          "302": { description: "Redirect to the long URL" },
          "404": { description: "Unknown code" },
          "429": { description: "Rate limited" },
        },
      },
    },
  },
};