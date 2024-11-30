const swaggerJsdoc = require("swagger-jsdoc");

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "CodeSpace API Documentation",
      version: "1.0.0",
      description: "API documentation for CodeSpace application",
    },
    servers: [
      {
        url: process.env.API_URL,
        description: "Development server",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        WebSocketEvents: {
          type: "object",
          properties: {
            joinRoom: {
              type: "string",
              description: "Event to join a codespace room",
              example: "my-codespace-slug",
            },
            leaveRoom: {
              type: "string",
              description: "Event to leave a codespace room",
              example: "my-codespace-slug",
            },
            codeChange: {
              type: "object",
              description: "Event for real-time code updates",
              properties: {
                content: {
                  type: "string",
                  description: "Updated code content",
                },
                language: {
                  type: "string",
                  description: "Programming language",
                },
                slug: {
                  type: "string",
                  description: "Codespace identifier",
                },
              },
            },
            codespaceSettingsChanged: {
              type: "object",
              description: "Event when codespace settings are updated",
              properties: {
                id: {
                  type: "integer",
                  description: "Codespace ID",
                },
                slug: {
                  type: "string",
                  description: "New codespace slug",
                },
                accessType: {
                  type: "string",
                  enum: ["public", "private", "shared"],
                  description: "New access type",
                },
                isArchived: {
                  type: "boolean",
                  description: "Archive status",
                },
                hasPasskey: {
                  type: "boolean",
                  description: "Whether codespace has a passkey",
                },
              },
            },
          },
        },
      },
    },
    tags: [
      {
        name: "Codespace",
        description: "Codespace operations",
      },
    ],
  },
  apis: ["./routes/*.js", "./controllers/*.js", "./server.js"],
};

const specs = swaggerJsdoc(options);
module.exports = specs;
