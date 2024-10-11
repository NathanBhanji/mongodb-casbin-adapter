// jest.config.ts

import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest', // Use ts-jest to handle TypeScript files
  testEnvironment: 'node', // Specify Node environment for backend projects
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  roots: ['<rootDir>/src'], // Root directory of tests
  transform: {
    '^.+\\.tsx?$': 'ts-jest', // Transform TypeScript files using ts-jest
  },
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1', // Map `@` prefix to `src` folder (optional)
  },
  collectCoverage: true, // Enable coverage collection
  coverageDirectory: 'coverage', // Specify coverage report directory
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/'], // Ignore coverage for these paths
};

export default config;
