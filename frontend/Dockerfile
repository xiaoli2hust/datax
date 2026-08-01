FROM node:22.22.0-alpine3.22@sha256:7aa86fa052f6e4b101557ccb56717cb4311be1334381f526fe013418fe157384 AS build

RUN corepack enable
WORKDIR /workspace
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY frontend/package.json ./frontend/package.json
RUN pnpm install --frozen-lockfile
COPY frontend ./frontend
RUN pnpm --filter @datax-studio/web build

FROM nginxinc/nginx-unprivileged:1.29.5-alpine@sha256:42a7d7f2ee23e9f5a1dcdf3647ba5c585bbd18f79e79cd817e70e8cd61c55779

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/frontend/dist /usr/share/nginx/html

EXPOSE 8080
