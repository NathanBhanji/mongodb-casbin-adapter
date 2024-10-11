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

async function setupEnforcer() {
  const adapter = await MongoAdapter.newAdapter({
    uri: 'mongodb://localhost:27017',
    database: 'casbin',
    collection: 'policies',
    dropCollectionOnManualSave: false,
    /* Default is false, set to true if you want to drop the collection when savePolicy is called */
    options: {
      /* MongoDB client options */
    },
  });

  const enforcer = await newEnforcer('path/to/model.conf', adapter);
  // Now you can use the enforcer
  const allowed = await enforcer.enforce('alice', 'data1', 'read');
  console.log(allowed ? 'Allow' : 'Deny');
}

setupEnforcer();
```
