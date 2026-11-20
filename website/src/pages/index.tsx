import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';

export default function Home(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  const heroSrc = useBaseUrl('/kavach-hero-dark.jpg');

  return (
    <Layout
      title={`${siteConfig.title} — Security without compromise`}
      description="Kavach. Observation-first security. Detect and report. Never contain.">
      <main className="kavach-home">
        <section className="kavach-home__hero" aria-label="Kavach">
          <div className="kavach-home__hero-copy">
            <p className="kavach-home__brand">Kavach.</p>
            <h1 className="kavach-home__headline">Security without compromise.</h1>
            <p className="kavach-home__lede">
              Observation-first endpoint, cloud, and AI security. Detect and
              report — never contain.
            </p>
            <div className="kavach-home__cta">
              <Link className="kavach-home__btn kavach-home__btn--primary" to="/docs/intro">
                Get started
              </Link>
              <Link
                className="kavach-home__btn kavach-home__btn--ghost"
                href="https://github.com/zyvorai/zyvor-kavach">
                GitHub
              </Link>
            </div>
          </div>
          <div className="kavach-home__visual" aria-hidden="true">
            <img
              className="kavach-home__visual-img"
              src={heroSrc}
              alt=""
              width={2400}
              height={1260}
              decoding="async"
              fetchPriority="high"
            />
          </div>
        </section>

        <section className="kavach-home__chapter kavach-home__chapter--rule">
          <p className="kavach-home__rule">Detect and report. Never contain.</p>
        </section>

        <section className="kavach-home__chapter">
          <h2 className="kavach-home__chapter-title">Investigate with clarity.</h2>
          <p className="kavach-home__chapter-lede">
            An Apple-quiet console for findings, fleet, hunt, and AI assist —
            built for analysts who need signal, not noise.
          </p>
        </section>

        <section className="kavach-home__chapter">
          <h2 className="kavach-home__chapter-title">See what matters.</h2>
          <p className="kavach-home__chapter-lede">
            Finance, public fleets, industry, space, and eBPF — observe only.
            Never freezes money, immobilizes vehicles, or commands spacecraft.
          </p>
        </section>

        <section className="kavach-home__chapter kavach-home__chapter--start">
          <h2 className="kavach-home__chapter-title">Start here.</h2>
          <p className="kavach-home__chapter-lede">
            Tutorial, architecture, and operator guides — ready when you are.
          </p>
          <div className="kavach-home__cta">
            <Link className="kavach-home__btn kavach-home__btn--primary" to="/docs/intro">
              Open the docs
            </Link>
          </div>
        </section>
      </main>
    </Layout>
  );
}
