import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, authHeaders, setAccessToken, tokenQuery } from "./api";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(async (_url: string, _init?: RequestInit) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

beforeEach(() => { localStorage.clear(); });
afterEach(() => { vi.unstubAllGlobals(); });

describe("api client", () => {
  it("sends the operator name, and the bearer token only when one is set", async () => {
    localStorage.setItem("agentshield.operator", "alice");
    let fetch = mockFetch(200, []);
    await api.targets();
    let headers = new Headers(fetch.mock.calls[0][1]?.headers);
    expect(headers.get("X-Operator")).toBe("alice");
    expect(headers.get("Authorization")).toBeNull();
    expect(tokenQuery("?")).toBe("");

    setAccessToken("tok-123");
    fetch = mockFetch(200, []);
    await api.targets();
    headers = new Headers(fetch.mock.calls[0][1]?.headers);
    expect(headers.get("Authorization")).toBe("Bearer tok-123");
    expect(tokenQuery("&")).toBe("&access_token=tok-123");
    expect(authHeaders().Authorization).toBe("Bearer tok-123");
  });

  it("turns FastAPI errors into readable ApiErrors and signals a missing token", async () => {
    mockFetch(422, { detail: [{ msg: "field required" }, { msg: "too long" }] });
    await expect(api.createPlan("R", { techniques: [] })).rejects.toMatchObject({ status: 422, message: "field required; too long" });
    const onAuth = vi.fn();
    window.addEventListener("agentshield:auth-required", onAuth);
    mockFetch(401, { detail: "Authentication required" });
    await expect(api.targets()).rejects.toBeInstanceOf(ApiError);
    expect(onAuth).toHaveBeenCalledTimes(1);
  });

  it("uses the documented routes for planning, execution, review and target edits", async () => {
    const fetch = mockFetch(200, {});
    await api.approvePlan("RUN-1", 3);
    await api.startAssessment("RUN-1");
    await api.reviewFinding(7, "dismissed", "benign");
    await api.updateTarget(4, { name: "x" });
    await api.planOptions("RUN-1");
    const calls = fetch.mock.calls.map(([url, init]) => `${init?.method ?? "GET"} ${url}`);
    expect(calls).toEqual(["POST /api/runs/RUN-1/plans/3/approve", "POST /api/runs/RUN-1/assessment/start",
      "POST /api/findings/7/review", "PUT /api/targets/4", "GET /api/runs/RUN-1/plan-options"]);
    expect(JSON.parse(String(fetch.mock.calls[2][1]?.body))).toEqual({ decision: "dismissed", note: "benign" });
  });
});
