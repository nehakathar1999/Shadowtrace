import React from "react";
import brandLogo from "../assets/STLOGO.png";

function MiniStat({ value, label }) {
  return (
    <div className="rounded-[22px] border border-[#e3edf6] bg-[#fbfdff] px-5 py-4">
      <div className="text-2xl font-semibold tracking-[-0.04em] text-slate-950">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-500">{label}</div>
    </div>
  );
}

export default function LandingPage({ onEnter, onGoAuth }) {
  return (
    <div className="min-h-screen overflow-hidden bg-white text-slate-900">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-[-8%] top-[-10%] h-[420px] w-[420px] rounded-full bg-sky-100/60 blur-[110px]" />
        <div className="absolute right-[-8%] top-[12%] h-[420px] w-[420px] rounded-full bg-cyan-100/55 blur-[120px]" />
        <div
          className="absolute inset-0 opacity-[0.22]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(148,163,184,0.14) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.14) 1px, transparent 1px)",
            backgroundSize: "90px 90px",
            maskImage: "linear-gradient(180deg, rgba(0,0,0,0.8), rgba(0,0,0,0.12))",
          }}
        />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-[1320px] flex-col px-6 py-8 sm:px-8 lg:px-10">
        <header className="flex items-center justify-between">
          <img src={brandLogo} alt="ShadowTrace" className="h-12 w-auto object-contain sm:h-14" />

          <div className="flex items-center gap-3">
            <button
              onClick={onGoAuth}
              className="rounded-full border border-[#d7e5f1] bg-white px-5 py-2.5 text-sm font-medium text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
            >
              Login
            </button>
            <button
              onClick={onGoAuth}
              className="rounded-full bg-[linear-gradient(135deg,#0284c7,#2563eb)] px-5 py-2.5 text-sm font-semibold text-white shadow-[0_14px_28px_rgba(37,99,235,0.22)] transition hover:-translate-y-0.5"
            >
              Sign up
            </button>
          </div>
        </header>

        <main className="flex flex-1 items-center justify-center py-10">
          <div className="grid w-full items-center gap-12 lg:grid-cols-[1.02fr_0.98fr]">
            <section className="max-w-[620px]">
              <div className="inline-flex items-center gap-2 rounded-full border border-[#dce8f3] bg-[#f7fbff] px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-sky-700">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
                Security workspace
              </div>

              <h1 className="mt-8 text-5xl font-semibold leading-[0.96] tracking-[-0.06em] text-slate-950 sm:text-6xl lg:text-[72px]">
                Clean vulnerability scanning,
                <span className="block text-sky-700">built to stay readable.</span>
              </h1>

              <p className="mt-6 max-w-[560px] text-lg leading-8 text-slate-600">
                ShadowTrace gives you a simple way to launch scans, review exposure, and generate reports without clutter or heavy visual noise.
              </p>

              <div className="mt-10 flex flex-col gap-4 sm:flex-row">
                <button
                  onClick={onGoAuth}
                  className="rounded-[22px] bg-[linear-gradient(135deg,#0284c7,#2563eb)] px-7 py-4 text-sm font-semibold uppercase tracking-[0.16em] text-white shadow-[0_18px_34px_rgba(37,99,235,0.22)] transition hover:-translate-y-0.5"
                >
                  Open account access
                </button>
                <button
                  onClick={onEnter}
                  className="rounded-[22px] border border-[#d7e5f1] bg-white px-7 py-4 text-sm font-semibold uppercase tracking-[0.16em] text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
                >
                  Preview scanner
                </button>
              </div>

              <div className="mt-10 grid gap-4 sm:grid-cols-3">
                <MiniStat value="Fast" label="scan flow" />
                <MiniStat value="Clear" label="risk review" />
                <MiniStat value="PDF" label="report export" />
              </div>
            </section>

            <section className="flex justify-center lg:justify-end">
              <div className="w-full max-w-[520px] rounded-[32px] border border-[#dfeaf4] bg-[#fbfdff] p-6 shadow-[0_24px_70px_rgba(15,23,42,0.08)]">
                <div className="rounded-[26px] border border-[#e5edf6] bg-white p-5">
                  <div className="flex items-center justify-between gap-4 border-b border-[#edf3f8] pb-4">
                    <div>
                      <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">Live scanner snapshot</div>
                      <div className="mt-2 text-xl font-semibold text-slate-950">Exposure overview</div>
                    </div>
                    <div className="rounded-full bg-emerald-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-emerald-700">
                      active
                    </div>
                  </div>

                  <div className="mt-5 space-y-4">
                    {[
                      ["Target", "192.168.1.0/24"],
                      ["Open services", "42 detected"],
                      ["Priority findings", "9 high severity"],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-[20px] bg-[#f4f8fc] px-4 py-4">
                        <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</div>
                        <div className="mt-2 text-lg font-semibold text-slate-900">{value}</div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-5 rounded-[22px] bg-[linear-gradient(135deg,#eff6ff,#f8fbff)] px-5 py-5">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-sky-700">Why it feels better</div>
                    <div className="mt-3 space-y-3 text-sm leading-7 text-slate-600">
                      <p>Focused scan entry.</p>
                      <p>Clean white layout for long review sessions.</p>
                      <p>Simple path from login to findings and reports.</p>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
