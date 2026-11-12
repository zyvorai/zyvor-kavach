import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';

export default function Home(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} — Security without compromise`}
      description="Zyvor Kavach — unified endpoint, cloud and AI security. Observation-first EDR with Netra XDR correlation for Linux and Kubernetes.">
      <main className="kavach-home">
        <section className="kavach-home__hero">
          <p className="kavach-home__eyebrow">by Zyvor</p>
          <h1 className="kavach-home__title">
            Kavach.
            <br />
            <span className="kavach-home__accent">Security without compromise.</span>
          </h1>
          <p className="kavach-home__lede">
            Unified endpoint, cloud and AI security — observation-first EDR with
            Netra XDR correlation, ransomware signals, SIEM export, and opt-in
            mTLS / Gateway API.
          </p>
          <div className="kavach-home__cta">
            <Link className="button button--secondary button--lg" to="/docs/intro">
              Get started
            </Link>
            <Link
              className="button button--outline button--secondary button--lg"
              href="https://github.com/zyvorai/zyvor-kavach">
              GitHub
            </Link>
          </div>
        </section>
        <section className="kavach-home__features">
          <h2>What ships today</h2>
          <ul>
            <li>
              <strong>EDR observation</strong> — process and file-activity
              signals, fleet heartbeats. No automatic containment.
            </li>
            <li>
              <strong>XDR with Netra</strong> — normalized network-event
              correlation by host and PID.
            </li>
            <li>
              <strong>Ransomware signals</strong> — mass file-activity is an
              investigative hint, not prevention.
            </li>
            <li>
              <strong>eBPF scaffold</strong> — optional exec sensor path under{' '}
              <code>bpf/</code>.
            </li>
            <li>
              <strong>SIEM export &amp; AI assistive scoring</strong> — findings
              API / JSONL; ranking assists analysts, does not act.
            </li>
            <li>
              <strong>mTLS &amp; Gateway API</strong> — both opt-in; NodePort
              :30899 for lab access.
            </li>
          </ul>
        </section>
      </main>
    </Layout>
  );
}
