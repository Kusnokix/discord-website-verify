# ---------- Stage 1: Build frontend ----------
FROM oven/bun:latest AS frontend-builder

WORKDIR /app/public

COPY public/ .

RUN bun install
RUN bun run build

# ---------- Stage 2: Build backend ----------
FROM oven/bun:latest AS backend-builder

WORKDIR /app

# Copy backend source
COPY src ./src
COPY tsconfig.json ./
COPY package.json ./

# Install backend deps
RUN bun install

# Copy EXISTING assets
COPY assets ./assets

# Copy NEW frontend build output (merge)
COPY --from=frontend-builder /app/public/dist/index.html ./assets/index.html
COPY --from=frontend-builder /app/public/dist/assets ./assets

# Compile backend into single binary
RUN bun build \
    --compile \
    --minify-whitespace \
    --minify-syntax \
    --outfile server \
    src/index.ts

# ---------- Stage 3: Runtime ----------
FROM oven/bun:latest

WORKDIR /app

# Copy compiled binary
COPY --from=backend-builder /app/server ./server

# Copy assets
COPY --from=backend-builder /app/assets ./assets

RUN chmod +x ./server

CMD ["./server"]
