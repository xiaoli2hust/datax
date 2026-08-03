# 第三方源码

`alibaba-datax/` 是从
[`alibaba/DataX`](https://github.com/alibaba/DataX) 的
`datax_v202309` 标签、提交
`9a1f88751e24314b083a74f1b83ef56d69ce98bd` 原样导入的源码树。

来源、上游 Git tree、许可证文件和本项目构建补丁由
`runtime/upstream.lock.json` 固定。发布构建只允许使用该仓库内源码，不在安装或启动阶段
下载 DataX。上游版权/许可告知和 NOTICE 原样保留在
`third_party/alibaba-datax/license.txt` 与 `third_party/alibaba-datax/NOTICE`；完整
Apache License 2.0 正文保存在 `third_party/licenses/Apache-2.0.txt`。

上游 NOTICE 标识 `opentsdbreader` 的部分源文件使用 LGPL-2.1-or-later；完整 LGPL 2.1
正文保存在 `third_party/licenses/LGPL-2.1-or-later.txt`。当前认证 Runtime 不编译或装入
`opentsdbreader`，但完整源码镜像仍保留对应告知和许可证。

本目录中的上游源码不代表 DataX Enterprise Studio 自身的许可证已经确定；根项目许可证
仍须由仓库所有者在正式公开发布前单独确认。
