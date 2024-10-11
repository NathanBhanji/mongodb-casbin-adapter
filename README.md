# MongoDB Adapter for Node Casbin

This is a MongoDB adapter for [Node Casbin](https://github.com/casbin/node-casbin). It provides policy storage and management using MongoDB for Casbin.

## Features

- Implements `FilteredAdapter`, `BatchAdapter`, and `UpdatableAdapter` interfaces
- Automatic index creation for optimized performance
- Timestamp support for policy rules (createdAt and updatedAt)

## Installation

```bash
npm install mongodb-casbin-adapter
```

## Usage

```typescript
import { newEnforcer } from 'casbin';
import { MongoAdapter } from 'mongodb-casbin-adapter';

const adapter = await MongoAdapter.newAdapter(
  'mongodb://localhost:27017', // MongoDB URI
  'casbin', // Database name
  'policies', // Collection name
  true, // Use filtered policies
  {
    /* MongoDB client options */
  },
);

const enforcer = await newEnforcer('path/to/model.conf', adapter);
const allowed = await enforcer.enforce('alice', 'data1', 'read');
```
