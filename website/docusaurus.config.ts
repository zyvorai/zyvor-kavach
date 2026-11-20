import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Kavach',
  tagline: 'Security without compromise.',
  favicon: 'img/favicon.svg',

  url: 'https://zyvorai.github.io',
  baseUrl: '/zyvor-kavach/',

  organizationName: 'zyvorai',
  projectName: 'zyvor-kavach',

  onBrokenLinks: 'throw',

  markdown: {
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  headTags: [
    {
      tagName: 'script',
      attributes: {type: 'application/ld+json'},
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: 'Kavach',
        applicationCategory: 'SecurityApplication',
        operatingSystem: 'Linux, Kubernetes',
        description:
          'Kavach. Observation-first security. Detect and report. Never contain.',
        url: 'https://zyvorai.github.io/zyvor-kavach/',
        codeRepository: 'https://github.com/zyvorai/zyvor-kavach',
      }),
    },
  ],

  staticDirectories: ['static', '../docs/social'],

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/zyvorai/zyvor-kavach/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'kavach-hero-dark.jpg',
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Kavach',
      logo: {
        alt: 'Kavach',
        src: 'img/favicon.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/zyvorai/zyvor-kavach',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Intro', to: '/docs/intro'},
            {label: 'Architecture', to: '/docs/architecture'},
            {label: 'Deploy remote', to: '/docs/deploy-remote'},
            {label: 'Agent mTLS', to: '/docs/agent-mtls'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/zyvorai/zyvor-kavach'},
            {
              label: 'License',
              href: 'https://github.com/zyvorai/zyvor-kavach/blob/main/LICENSE',
            },
          ],
        },
        {
          title: 'Zyvor Enterprise',
          items: [
            {label: 'zyvor.dev', href: 'https://zyvor.dev'},
            {label: 'sales@zyvor.dev', href: 'mailto:sales@zyvor.dev'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Zyvor. Zyvor Production License v1.0.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
