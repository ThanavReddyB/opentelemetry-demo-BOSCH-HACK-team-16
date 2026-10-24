"""Scenario catalogue for the on-call agent test bench: what to break, and what a correct answer looks like.

Each single scenario injects one fault and states what the agent may call it:
  components  failing_component values that count as a correct diagnosis (first = the real culprit)
  classes     acceptable fault_class values
  outcome     "resolve" (an allowlisted fix exists) or "escalate" (no fix exists; escalating with findings
              is correct, a verified fix is accepted too)

A combo is single ids joined with "+" (e.g. payment-fail+cache-down); every fault keeps its own expectation.
Pure data plus small helpers: nothing here touches Docker or the agent.
"""

FAULT_CLASSES = (
    "app_error", "partial_failure", "dependency_down", "container_crash_or_restart", "memory_leak",
    "cpu_saturation", "traffic_flood", "network_degradation", "resource_starvation", "latency_regression", "unknown",
)
OUTCOMES = ("resolve", "escalate")
INJECT_KINDS = ("flag", "stop", "starve", "net", "crashloop")


def flag(name, variant="on"):
    return {"kind": "flag", "flag": name, "variant": variant}


def stop(service):
    return {"kind": "stop", "service": service}


def starve(service, cpus="0.05", memory=None):
    return {"kind": "starve", "service": service, "cpus": cpus, "memory": memory}


def net_delay(service, delay="400ms", jitter="50ms"):
    return {"kind": "net", "service": service, "delay": delay, "jitter": jitter}


def net_loss(service, loss="30%"):
    return {"kind": "net", "service": service, "delay": None, "jitter": None, "loss": loss}


def crashloop(service, every_s=45):
    """Kill the service's main process every `every_s` seconds; its restart policy brings it back each time."""
    return {"kind": "crashloop", "service": service, "every_s": every_s}


def _s(title, inject, components, classes, outcome="resolve"):
    return {"title": title, "inject": inject,
            "expect": {"components": list(components), "classes": list(classes), "outcome": outcome}}


SCENARIOS = {
    "payment-fail": _s("Payment rejects every charge", flag("paymentFailure", "100%"),
                       ["payment"], ["app_error"]),
    "payment-unreachable": _s("Checkout cannot reach payment", flag("paymentUnreachable"),
                              ["payment", "checkout"], ["dependency_down", "app_error"]),
    "cart-fail": _s("Cart EmptyCart always fails", flag("cartFailure", "100%"),
                    ["cart"], ["app_error", "partial_failure"]),
    "product-fail": _s("Product catalog fails for one product id", flag("productCatalogFailure"),
                       ["product-catalog"], ["partial_failure", "app_error"]),
    "ad-fail": _s("Ad service errors on GetAds", flag("adFailure"),
                  ["ad"], ["app_error"]),
    "ad-cpu": _s("Ad service burns CPU", flag("adHighCpu"),
                 ["ad"], ["cpu_saturation", "latency_regression"]),
    "ad-gc": _s("Ad service forces full GCs", flag("adManualGc"),
                ["ad"], ["cpu_saturation", "latency_regression", "app_error"]),
    "reco-leak": _s("Recommendation cache leaks memory", flag("recommendationCacheFailure"),
                    ["recommendation"], ["memory_leak", "latency_regression"]),
    "email-leak": _s("Email service leaks memory (1000x)", flag("emailMemoryLeak", "1000x"),
                     ["email"], ["memory_leak"]),
    "traffic-flood": _s("Load generator floods the homepage", flag("loadGeneratorFloodHomepage"),
                        ["frontend", "load-generator", "frontend-proxy"], ["traffic_flood"]),
    "shipping-slow": _s("International shipping quotes take 10s", flag("intlShippingSlowdown", "10sec"),
                        ["shipping"], ["latency_regression"]),
    "image-slow": _s("Product images load 10s late", flag("imageSlowLoad", "10sec"),
                     ["image-provider", "frontend-proxy"], ["latency_regression", "network_degradation"]),
    "catalog-lock": _s("Product catalog lock contention", flag("productCatalogLockContention"),
                       ["product-catalog"], ["latency_regression", "cpu_saturation"]),
    "cache-down": _s("Cart cache valkey-cart stopped", stop("valkey-cart"),
                     ["valkey-cart"], ["dependency_down", "container_crash_or_restart"]),
    "db-down": _s("Catalog database astronomy-db stopped", stop("astronomy-db"),
                  ["astronomy-db"], ["dependency_down", "container_crash_or_restart"]),
    "svc-down": _s("Currency service stopped", stop("currency"),
                   ["currency"], ["container_crash_or_restart", "dependency_down"]),
    "starve": _s("Recommendation capped at 0.05 CPU", starve("recommendation", "0.05"),
                 ["recommendation"], ["resource_starvation", "cpu_saturation", "latency_regression"]),
    "net-delay": _s("400ms +/- 50ms network delay on cart", net_delay("cart"),
                    ["cart", "checkout", "frontend"], ["network_degradation", "latency_regression"], "escalate"),
    "net-loss": _s("30% packet loss on cart's network", net_loss("cart"),
                   ["cart", "checkout", "frontend"], ["network_degradation", "app_error", "latency_regression"], "escalate"),
    "crash-loop": _s("Currency crashes every 45s and is restarted", crashloop("currency"),
                     ["currency"], ["container_crash_or_restart", "dependency_down"], "escalate"),
}
for _id, _sc in SCENARIOS.items():
    _sc["id"] = _id

COMBOS = ["payment-fail+cache-down", "ad-fail+svc-down", "product-fail+reco-leak"]
SUITES = {
    "smoke": ["cart-fail", "payment-fail", "svc-down"],
    "core": ["payment-fail", "cart-fail", "product-fail", "ad-cpu", "reco-leak", "traffic-flood",
             "cache-down", "svc-down", "net-delay"],
    "infra": ["cache-down", "db-down", "svc-down", "starve", "crash-loop", "net-delay", "net-loss"],
    "combos": COMBOS,
    "all": [*SCENARIOS, *COMBOS],
}


def parse_combo(text):
    """'a+b' -> ['a', 'b']. Raises ValueError on an empty, unknown or repeated id."""
    ids = [p.strip() for p in str(text).split("+")]
    if not all(ids):
        raise ValueError(f"empty scenario id in {text!r}")
    unknown = [i for i in ids if i not in SCENARIOS]
    if unknown:
        raise ValueError(f"unknown scenario id(s): {', '.join(unknown)} (see: python testbench/run.py list)")
    if len(set(ids)) != len(ids):
        raise ValueError(f"repeated scenario id in {text!r}")
    return ids


def expand(targets):
    """Suite names, single ids and a+b combos -> list of runs, each run a list of single ids."""
    runs = []
    for t in [targets] if isinstance(targets, str) else targets:
        runs += [parse_combo(x) for x in SUITES[t]] if t in SUITES else [parse_combo(t)]
    return runs


def combo_id(ids):
    return "+".join(ids)


def describe(spec):
    """One-line description of an inject spec."""
    k = spec["kind"]
    if k == "flag":
        return f"flag {spec['flag']}={spec['variant']}"
    if k == "stop":
        return f"stop {spec['service']}"
    if k == "starve":
        return f"starve {spec['service']} cpus={spec['cpus']}" + (f" memory={spec['memory']}" if spec.get("memory") else "")
    if k == "crashloop":
        return f"crash loop on {spec['service']} every {spec['every_s']}s"
    if spec.get("loss"):
        return f"net loss {spec['loss']} on {spec['service']}"
    return f"net delay {spec['delay']}~{spec['jitter']} on {spec['service']}"


def expected_text(ids):
    """'payment/resolve + valkey-cart/resolve' for a run."""
    return " + ".join(f"{SCENARIOS[i]['expect']['components'][0]}/{SCENARIOS[i]['expect']['outcome']}" for i in ids)
