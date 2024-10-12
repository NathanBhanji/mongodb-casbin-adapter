import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { newEnforcer, Enforcer, Model } from 'casbin';
import { MongoAdapter } from './adapter';
import { MongoServerError } from 'mongodb';

describe('MongoAdapter', () => {
  let mongoServer: MongoMemoryReplSet;
  let mongoUri: string;
  let adapter: MongoAdapter;
  let enforcer: Enforcer;
  let client: MongoClient;

  beforeAll(async () => {
    try {
      mongoServer = await MongoMemoryReplSet.create({
        replSet: { count: 1, storageEngine: 'wiredTiger' },
      });
      mongoUri = mongoServer.getUri();
      client = new MongoClient(mongoUri);
      await client.connect();
      console.log('Successfully connected to the in-memory MongoDB instance');
    } catch (error) {
      console.error(
        'Failed to connect to the in-memory MongoDB instance:',
        error,
      );
      throw error;
    }
  });

  afterAll(async () => {
    await adapter.close();
    await client.close();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    adapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
    });
    const model = new Model();
    model.addDef('r', 'r', 'sub, obj, act');
    model.addDef('p', 'p', 'sub, obj, act');
    model.addDef('e', 'e', 'some(where (p.eft == allow))');
    model.addDef(
      'm',
      'm',
      'r.sub == p.sub && r.obj == p.obj && r.act == p.act',
    );

    enforcer = await newEnforcer(model, adapter);
  });

  afterEach(async () => {
    await adapter.close();
    await client.db('casbin').collection('policies').deleteMany({});
  });

  const getDbPolicies = async () => {
    try {
      const collection = client.db('casbin').collection('policies');
      return await collection.find({}).toArray();
    } catch (error) {
      if (error instanceof MongoServerError) {
        console.error('MongoDB operation failed:', error);
      } else {
        console.error('Unexpected error during database operation:', error);
      }
      throw error;
    }
  };

  it('should add a new policy', async () => {
    await enforcer.addPolicy('alice', 'data1', 'read');
    const result = await enforcer.enforce('alice', 'data1', 'read');
    expect(result).toBe(true);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    expect(dbPolicies[0]).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'alice',
        v1: 'data1',
        v2: 'read',
      }),
    );
  });

  it('should remove an existing policy', async () => {
    await enforcer.addPolicy('bob', 'data2', 'write');
    await enforcer.removePolicy('bob', 'data2', 'write');
    const result = await enforcer.enforce('bob', 'data2', 'write');
    expect(result).toBe(false);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(0);
  });

  it('should update an existing policy', async () => {
    await enforcer.addPolicy('charlie', 'data3', 'read');
    await enforcer.updatePolicy(
      ['charlie', 'data3', 'read'],
      ['charlie', 'data3', 'write'],
    );
    const readResult = await enforcer.enforce('charlie', 'data3', 'read');
    const writeResult = await enforcer.enforce('charlie', 'data3', 'write');
    expect(readResult).toBe(false);
    expect(writeResult).toBe(true);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    expect(dbPolicies[0]).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'charlie',
        v1: 'data3',
        v2: 'write',
      }),
    );
  });

  it('should update the updatedAt field when updating a policy', async () => {
    await enforcer.addPolicy('noah', 'data15', 'read');

    let dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    const initialUpdatedAt = dbPolicies[0]?.['updatedAt'];

    // Wait for a short time to ensure the updatedAt timestamp will be different
    await new Promise((resolve) => setTimeout(resolve, 100));

    await enforcer.updatePolicy(
      ['noah', 'data15', 'read'],
      ['noah', 'data15', 'write'],
    );

    dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    const updatedPolicy = dbPolicies[0];

    expect(updatedPolicy).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'noah',
        v1: 'data15',
        v2: 'write',
      }),
    );

    expect(updatedPolicy?.['updatedAt']).toBeInstanceOf(Date);
    expect(updatedPolicy?.['updatedAt']).not.toEqual(initialUpdatedAt);
    expect(updatedPolicy?.['updatedAt'].getTime()).toBeGreaterThan(
      initialUpdatedAt.getTime(),
    );
    expect(updatedPolicy?.['createdAt']).toEqual(dbPolicies[0]?.['createdAt']);
  });

  it('should load all policies from the database', async () => {
    await enforcer.addPolicy('david', 'data4', 'read');
    await enforcer.addPolicy('eve', 'data5', 'write');

    const newEnforcerInstance = await newEnforcer(enforcer.getModel(), adapter);
    await newEnforcerInstance.loadPolicy();

    const result1 = await newEnforcerInstance.enforce('david', 'data4', 'read');
    const result2 = await newEnforcerInstance.enforce('eve', 'data5', 'write');
    expect(result1).toBe(true);
    expect(result2).toBe(true);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(2);
    expect(dbPolicies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ptype: 'p',
          v0: 'david',
          v1: 'data4',
          v2: 'read',
        }),
        expect.objectContaining({
          ptype: 'p',
          v0: 'eve',
          v1: 'data5',
          v2: 'write',
        }),
      ]),
    );
  });

  it('should save all policies to the database', async () => {
    await enforcer.addPolicy('frank', 'data6', 'read');
    await enforcer.addPolicy('grace', 'data7', 'write');
    await enforcer.savePolicy();

    const newAdapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
    });
    const newEnforcerInstance = await newEnforcer(
      enforcer.getModel(),
      newAdapter,
    );
    await newEnforcerInstance.loadPolicy();

    const result1 = await newEnforcerInstance.enforce('frank', 'data6', 'read');
    const result2 = await newEnforcerInstance.enforce(
      'grace',
      'data7',
      'write',
    );
    expect(result1).toBe(true);
    expect(result2).toBe(true);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(2);
    expect(dbPolicies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ptype: 'p',
          v0: 'frank',
          v1: 'data6',
          v2: 'read',
        }),
        expect.objectContaining({
          ptype: 'p',
          v0: 'grace',
          v1: 'data7',
          v2: 'write',
        }),
      ]),
    );

    await newAdapter.close();
  });

  it('should remove policies based on filter', async () => {
    const newAdapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
      filtered: true,
    });

    const filteredEnforcer = await newEnforcer(enforcer.getModel(), newAdapter);
    filteredEnforcer.loadPolicy();

    await filteredEnforcer.addPolicy('harry', 'data8', 'read');
    await filteredEnforcer.addPolicy('harry', 'data9', 'write');
    await filteredEnforcer.addPolicy('ivy', 'data10', 'read');

    await filteredEnforcer.removeFilteredPolicy(0, 'harry');

    const result1 = await filteredEnforcer.enforce('harry', 'data8', 'read');
    const result2 = await filteredEnforcer.enforce('harry', 'data9', 'write');
    const result3 = await filteredEnforcer.enforce('ivy', 'data10', 'read');

    expect(result1).toBe(false);
    expect(result2).toBe(false);
    expect(result3).toBe(true);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    expect(dbPolicies[0]).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'ivy',
        v1: 'data10',
        v2: 'read',
      }),
    );
    await newAdapter.close();
  });

  it('should add multiple policies', async () => {
    const policies = [
      ['jack', 'data11', 'read'],
      ['kate', 'data12', 'write'],
    ];

    await enforcer.addPolicies(policies);

    const result1 = await enforcer.enforce('jack', 'data11', 'read');
    const result2 = await enforcer.enforce('kate', 'data12', 'write');

    expect(result1).toBe(true);
    expect(result2).toBe(true);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(2);
    expect(dbPolicies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ptype: 'p',
          v0: 'jack',
          v1: 'data11',
          v2: 'read',
        }),
        expect.objectContaining({
          ptype: 'p',
          v0: 'kate',
          v1: 'data12',
          v2: 'write',
        }),
      ]),
    );
  });

  it('should remove multiple policies', async () => {
    const policies = [
      ['liam', 'data13', 'read'],
      ['mia', 'data14', 'write'],
    ];

    await enforcer.addPolicies(policies);
    await enforcer.removePolicies(policies);

    const result1 = await enforcer.enforce('liam', 'data13', 'read');
    const result2 = await enforcer.enforce('mia', 'data14', 'write');

    expect(result1).toBe(false);
    expect(result2).toBe(false);

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(0);
  });

  it('should set createdAt and updatedAt to the same value when adding a new policy', async () => {
    await enforcer.addPolicy('olivia', 'data16', 'read');

    const dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    const newPolicy = dbPolicies[0];

    expect(newPolicy).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'olivia',
        v1: 'data16',
        v2: 'read',
      }),
    );

    expect(newPolicy?.['createdAt']).toBeInstanceOf(Date);
    expect(newPolicy?.['updatedAt']).toBeInstanceOf(Date);
    expect(newPolicy?.['createdAt']).toEqual(newPolicy?.['updatedAt']);
  });

  it('should create the correct indexes on the policies collection', async () => {
    const newAdapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'testing-indexes',
    });

    const collection = client.db('casbin').collection('testing-indexes');
    const indexes = await collection.indexes();

    expect(indexes).toContainEqual(
      expect.objectContaining({
        name: 'ptype_v0_v1_v2_v3_v4_v5_compound_index',
        key: { ptype: 1, v0: 1, v1: 1, v2: 1, v3: 1, v4: 1, v5: 1 },
      }),
    );

    expect(indexes).toContainEqual(
      expect.objectContaining({
        name: 'createdAt_1',
        key: { createdAt: 1 },
      }),
    );

    expect(indexes).toContainEqual(
      expect.objectContaining({
        name: 'updatedAt_1',
        key: { updatedAt: 1 },
      }),
    );
    await newAdapter.close();
  });

  it('should drop the collection when dropCollectionOnManualSave is true', async () => {
    const dropCollectionAdapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'drop_test_policies',
      dropCollectionOnManualSave: true,
    });

    const model = new Model();
    model.addDef('r', 'r', 'sub, obj, act');
    model.addDef('p', 'p', 'sub, obj, act');
    model.addDef('e', 'e', 'some(where (p.eft == allow))');
    model.addDef(
      'm',
      'm',
      'r.sub == p.sub && r.obj == p.obj && r.act == p.act',
    );

    const dropTestEnforcer = await newEnforcer(model, dropCollectionAdapter);

    await dropTestEnforcer.addPolicy('alice', 'data1', 'read');
    await dropTestEnforcer.addPolicy('bob', 'data2', 'write');

    const dbPolicies = await client
      .db('casbin')
      .collection('drop_test_policies')
      .find({})
      .toArray();
    expect(dbPolicies).toHaveLength(2);

    const changeStream = client
      .db('casbin')
      .watch([
        { $match: { operationType: 'drop', 'ns.coll': 'drop_test_policies' } },
      ]);

    try {
      let dropDetected = false;
      changeStream.on('change', (change) => {
        if (
          change.operationType === 'drop' &&
          change.ns.coll === 'drop_test_policies'
        ) {
          dropDetected = true;
        }
      });

      await dropTestEnforcer.savePolicy();

      expect(dropDetected).toBe(true);
    } finally {
      await changeStream.close();
      await dropCollectionAdapter.close();
    }
  });

  it('should throw an error when creating adapter with empty URI', async () => {
    await expect(
      MongoAdapter.newAdapter({
        uri: '',
        database: 'casbin',
        collection: 'policies',
      }),
    ).rejects.toThrow(
      'MongoDB URI is required. Please provide a valid connection string.',
    );
  });

  it('should throw an error when failing to create MongoClient', async () => {
    const invalidUri = 'invalid://uri';
    await expect(
      MongoAdapter.newAdapter({
        uri: invalidUri,
        database: 'casbin',
        collection: 'policies',
      }),
    ).rejects.toThrow(/Failed to create MongoClient:/);
  });

  it('should throw an error when failing to load filtered policy', async () => {
    const adapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
      filtered: true,
    });

    const model = new Model();

    jest.spyOn(adapter['mongoClient'], 'db').mockImplementationOnce(() => {
      throw new Error('Database error');
    });

    await expect(adapter.loadFilteredPolicy(model)).rejects.toThrow(
      /Failed to load filtered policy:/,
    );
    await adapter.close();
  });

  it('should throw an error when failing to create collection or indexes', async () => {
    const adapter = new MongoAdapter(mongoUri, 'casbin', 'policies');

    jest.spyOn(adapter['mongoClient'], 'db').mockImplementationOnce(() => {
      throw new Error('Database error');
    });

    await expect(adapter.createDBIndex()).rejects.toThrow(
      /Failed to create collection or database indexes:/,
    );
    await adapter.close();
  });

  it('should throw an error when failing to open MongoDB connection', async () => {
    await expect(
      MongoAdapter.newAdapter({
        uri: 'mongodb://invalid-host:27017',
        database: 'casbin',
        collection: 'policies',
        options: {
          serverSelectionTimeoutMS: 1000,
        },
      }),
    ).rejects.toThrow(/Failed to open MongoDB connection and create indexes:/);
  });

  it('should throw an error when failing to get collection', async () => {
    const adapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
    });

    jest.spyOn(adapter['mongoClient'], 'db').mockImplementationOnce(() => {
      throw new Error('Database error');
    });

    expect(() => adapter['getCollection']()).toThrow(
      /Failed to get collection 'policies':/,
    );
    await adapter.close();
  });

  it('should throw an error when failing to get database', async () => {
    const adapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
    });

    jest.spyOn(adapter['mongoClient'], 'db').mockImplementationOnce(() => {
      throw new Error('Client error');
    });

    expect(() => adapter['getDatabase']()).toThrow(
      /Failed to get database 'casbin':/,
    );
    await adapter.close();
  });

  it('should throw an error when failing to clear collection', async () => {
    const adapter = await MongoAdapter.newAdapter({
      uri: mongoUri,
      database: 'casbin',
      collection: 'policies',
    });

    jest.spyOn(adapter['mongoClient'], 'db').mockImplementationOnce(() => {
      throw new Error('Database error');
    });

    await expect(adapter['clearCollection']()).rejects.toThrow(
      /Failed to clear collection 'policies':/,
    );
    await adapter.close();
  });

  it('should throw an error when calling close() without an active connection', async () => {
    const adapter = new MongoAdapter(mongoUri, 'casbin', 'policies');

    adapter['mongoClient'].close = jest
      .fn()
      .mockRejectedValue(new Error('Not connected'));

    await expect(adapter.close()).rejects.toThrow(
      'Failed to close MongoDB connection: Not connected. Please ensure the client is connected before closing.',
    );
  });

  it('should update policy from an older more complex version to a simpler version and remove unused fields while preserving createdAt', async () => {
    const model = new Model();
    model.addDef('r', 'r', 'sub, obj, act, type, owner');
    model.addDef('p', 'p', 'sub, obj, act, type, owner');
    model.addDef('e', 'e', 'some(where (p.eft == allow))');
    model.addDef(
      'm',
      'm',
      'r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.type == p.type && r.owner == p.owner',
    );

    const v5Enforcer = await newEnforcer(model, adapter);

    await v5Enforcer.addPolicy(
      'alice',
      'data1',
      'read',
      'confidential',
      'admin',
    );

    let dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    const originalCreatedAt = dbPolicies[0]?.['createdAt'];
    expect(dbPolicies[0]).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'alice',
        v1: 'data1',
        v2: 'read',
        v3: 'confidential',
        v4: 'admin',
        createdAt: expect.any(Date),
      }),
    );

    const updatedModel = new Model();
    updatedModel.addDef('r', 'r', 'sub, obj, act');
    updatedModel.addDef('p', 'p', 'sub, obj, act');
    updatedModel.addDef('e', 'e', 'some(where (p.eft == allow))');
    updatedModel.addDef(
      'm',
      'm',
      'r.sub == p.sub && r.obj == p.obj && r.act == p.act',
    );

    const v3Enforcer = await newEnforcer(updatedModel, adapter);

    await v3Enforcer.updatePolicy(
      ['alice', 'data1', 'read', 'confidential', 'admin'],
      ['alice', 'data1', 'read'],
    );

    dbPolicies = await getDbPolicies();
    expect(dbPolicies).toHaveLength(1);
    expect(dbPolicies[0]).toEqual(
      expect.objectContaining({
        ptype: 'p',
        v0: 'alice',
        v1: 'data1',
        v2: 'read',
        createdAt: originalCreatedAt,
      }),
    );
    expect(dbPolicies[0]).not.toHaveProperty('v3');
    expect(dbPolicies[0]).not.toHaveProperty('v4');
    expect(dbPolicies[0]?.['createdAt']).toEqual(originalCreatedAt);

    const result = await v3Enforcer.enforce('alice', 'data1', 'read');
    expect(result).toBe(true);
  });
});
