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
    adapter = await MongoAdapter.newAdapter(mongoUri, 'casbin', 'policies');
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

    const newAdapter = await MongoAdapter.newAdapter(
      mongoUri,
      'casbin',
      'policies',
    );
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
    await enforcer.addPolicy('harry', 'data8', 'read');
    await enforcer.addPolicy('harry', 'data9', 'write');
    await enforcer.addPolicy('ivy', 'data10', 'read');

    await enforcer.removeFilteredPolicy(0, 'harry');

    const result1 = await enforcer.enforce('harry', 'data8', 'read');
    const result2 = await enforcer.enforce('harry', 'data9', 'write');
    const result3 = await enforcer.enforce('ivy', 'data10', 'read');

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
    const newAdapter = await MongoAdapter.newAdapter(
      mongoUri,
      'casbin',
      'testing-indexes',
    );

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
});
