// swagger.js
const swaggerJSDoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Prep360 API Docs',
      version: '1.0.0',
      description: 'API documentation for Prep360 backend',
    },
    servers: [{ url: 'http://localhost:3000' }],
  },
  apis: ['./server.js', './routes/*.js'], // <- Update this if needed
};

const swaggerSpec = swaggerJSDoc(options);
module.exports = swaggerSpec;
