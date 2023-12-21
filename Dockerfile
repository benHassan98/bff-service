FROM node:16

WORKDIR /usr/src/app

COPY . .

RUN npm intall

EXPOSE 8080

CMD ["node", "server.js"]
