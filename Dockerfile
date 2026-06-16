FROM node:20-alpine

# ffmpeg/ffprobe for audio duration + silence-padding; curl for healthcheck
RUN apk add --no-cache ffmpeg curl

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/login.html >/dev/null || exit 1

CMD ["npm", "start"]
