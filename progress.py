"""Completed-stage progress; independent of elapsed time and network outcomes."""
def stage_plan(mtu, tune):
    stages = [
        ("configuration", "读取网卡、路由和 DNS 配置"),
        ("dns", "测试 DNS 解析"),
        ("dns_validation", "验证 DNS 实验"),
        ("performance", "测试实际网络性能"),
    ]
    if mtu:
        stages.append(("mtu", "探测 MTU"))
    stages.append(("baseline", "验证性能基线"))
    if tune:
        stages.extend([
            ("tuning", "执行自适应并发寻优"),
            ("history", "认证局部和历史证据"),
        ])
    stages.extend([
        ("diagnostics", "整理 IPv6 与网络诊断"),
        ("export", "生成并保存报告"),
    ])
    return tuple(stages)


class StageProgress:
    def __init__(self, mtu, tune):
        self.stages = stage_plan(mtu, tune)
        self.completed = 0
        self.active = None
        self.state = "running"

    @property
    def total(self):
        return len(self.stages)

    def enter(self, key):
        if self.state != "running":
            return False
        index = self.completed + int(self.active is not None)
        if index >= self.total or self.stages[index][0] != key:
            raise ValueError("Unexpected stage: " + key)
        self.completed = index
        self.active = self.stages[index][1]
        return True

    def finish(self):
        if self.state != "running":
            return False
        if self.active is None or self.completed != self.total - 1:
            raise ValueError("Cannot complete before report export")
        self.completed = self.total
        self.active = None
        self.state = "complete"
        return True

    def abort(self, cancelled=False):
        if self.state != "running":
            return False
        self.state = "cancelled" if cancelled else "failed"
        return True

    def label(self):
        prefix = f"阶段进度 {self.completed}/{self.total}（{self.completed * 100 // self.total}%）"
        if self.state == "complete":
            return prefix + " · 已完成"
        if self.state != "running":
            return prefix + (" · 已取消" if self.state == "cancelled" else " · 失败")
        return prefix + (" · 正在" + self.active if self.active else " · 准备开始")


def metric(value, unit="", digits=2):
    """Display-only formatter; missing data never becomes a zero measurement."""
    import math
    if type(value) not in (int, float) or not math.isfinite(value):
        return "未测得"
    return f"{value:.{digits}f}{unit}"


def batch_detail(row):
    return (f"请求成功 {row.get('success', 0)}/{row.get('planned', 0)}；"
            f"正文 {row.get('actual_bytes', 0)}/{row.get('expected_bytes', 0)} 字节；"
            f"有效速率 {metric(row.get('aggregate_mbps'), ' Mbps', 3)}；"
            f"耗时 {metric(row.get('elapsed_s'), ' 秒')}；"
            + ("批次完成" if row.get("status") == "OK" else "批次未完整成功"))
