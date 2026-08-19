# Hugging Face Docker 部署占位

镜像构建由 GitHub Actions 完成，当前工作流不会在开发机执行 Docker 构建。手动运行 `Build Private Image` 后，把产出的 GHCR 镜像用于 Docker Space。

部署项目应在自己的私有变量或 Secret 中填写：

- `HF_SPACE_ID`：目标 Space，例如 `owner/private-space`。
- `HF_CONTAINER_NAME`：写入镜像 OCI label 的中性名称；Hugging Face 的实际运行容器名由平台分配，不能由镜像强制指定。
- `SINGBOX_OUTBOUND_JSON` 或 `SINGBOX_SUBSCRIPTION_URL`：只作为运行时 Secret 注入，不要提交到仓库。

Space 需要把应用端口映射到 `7860`。如果 GHCR 镜像为私有，需在 Space 的 Secret 中配置具有只读权限的 registry token；也可以把同一镜像推送到组织自己的私有镜像仓库。

容器启动时会从运行时环境生成 Sing-box 配置，配置文件写入容器临时目录并使用 `0600` 权限。未设置 Sing-box 来源时，应用保持原有直连/环境代理行为。

运行时进程名默认随机生成，例如 `worker-a1b2c3` 和 `helper-d4e5f6`。可用 `PROCESS_NAME` 与 `SINGBOX_PROCESS_NAME` 覆盖，Linux 进程 comm 最长 15 个字符。
