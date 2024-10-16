/*
 * This file contains code originally licensed under the MIT License (© Rex Isaac Raphael, 2019).
 * Modifications © Nathan Bhanji, 2024 are licensed under the Apache License, Version 2.0.
 * For details, see the LICENSE file in the project root.
 */

import {
  Helper,
  Model,
  BatchAdapter,
  FilteredAdapter,
  UpdatableAdapter,
} from 'casbin';
import {
  Collection,
  MongoClient,
  MongoClientOptions,
  Db,
  Filter,
} from 'mongodb';
import winston, { Logger } from 'winston';

interface CasbinRule {
  ptype?: string;
  v0?: string;
  v1?: string;
  v2?: string;
  v3?: string;
  v4?: string;
  v5?: string;
}

interface CasbinRuleWithUpdatedAt extends CasbinRule {
  updatedAt: Date;
}

interface CasbinRuleWithTimestamps extends CasbinRuleWithUpdatedAt {
  createdAt: Date;
}
class MongoAdapterError extends Error {
  constructor(
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'MongoAdapterError';

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MongoAdapterError);
    }

    // Preserves the original error's stack if available
    if (cause instanceof Error && cause.stack) {
      this.stack = `${this.stack}\n\nCaused by:\n${cause.stack}`;
    }
  }
}

/**
 * MongoAdapter represents the MongoDB adapter for policy storage.
 */
export class MongoAdapter
  implements FilteredAdapter, BatchAdapter, UpdatableAdapter
{
  private readonly databaseName: string;
  private readonly mongoClient: MongoClient;
  private readonly collectionName: string;
  private readonly dropCollectionOnManualSave: boolean;
  private logger: Logger;
  public useFilter: boolean = false;

  constructor(
    uri: string,
    database: string,
    collection: string,
    filtered: boolean = false,
    options?: MongoClientOptions,
    dropCollectionOnManualSave: boolean = false,
  ) {
    if (!uri) {
      throw new MongoAdapterError('MongoDB URI is required.');
    }

    this.databaseName = database;
    this.collectionName = collection;
    this.useFilter = filtered;
    this.dropCollectionOnManualSave = dropCollectionOnManualSave;

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()],
    });

    try {
      this.mongoClient = new MongoClient(uri, options);
    } catch (error) {
      throw this.wrapError(error, 'Failed to create MongoClient');
    }
  }

  public static async newAdapter({
    uri,
    options,
    database,
    collection,
    filtered,
    dropCollectionOnManualSave,
  }: {
    uri: string;
    options?: MongoClientOptions;
    database: string;
    collection: string;
    filtered?: boolean;
    dropCollectionOnManualSave?: boolean;
  }): Promise<MongoAdapter> {
    const adapter = new MongoAdapter(
      uri,
      database,
      collection,
      filtered,
      options,
      dropCollectionOnManualSave,
    );
    await adapter.open();
    return adapter;
  }

  isFiltered(): boolean {
    return this.useFilter;
  }

  public async close() {
    try {
      await this.mongoClient.close();
    } catch (error) {
      throw this.wrapError(error, 'Failed to close MongoDB connection');
    }
  }

  /**
   * loadPolicy loads all policy rules from the database.
   */
  public async loadPolicy(model: Model) {
    await this.loadFilteredPolicy(model);
  }

  /**
   * loadPolicy loads filtered policy rules from the database.
   */
  public async loadFilteredPolicy(model: Model, filter?: Filter<unknown>) {
    try {
      const lines = await this.getFilteredPolicyLines(filter);
      lines.forEach((line) => this.loadPolicyLine(line as CasbinRule, model));
    } catch (error) {
      throw this.wrapError(error, 'Failed to load filtered policy');
    }
  }

  /**
   * savePolicy deletes all existing policy from database and saves the current policy state to the database.
   */
  public async savePolicy(model: Model): Promise<boolean> {
    await this.clearCollection();
    const allRules = this.getAllPolicyRules(model);
    if (allRules.length > 0) {
      await this.getCollection().insertMany(allRules);
    }
    return true;
  }

  private extractPolicyRules(model: Model, key: 'p' | 'g'): CasbinRule[] {
    const astMap = model.model.get(key);
    if (!astMap) {
      return [];
    }

    return Array.from(astMap.entries()).flatMap(([ptype, ast]) =>
      ast.policy.map((rule) => this.savePolicyLine(ptype, rule)),
    );
  }

  /**
   * addPolicy adds a policy rule to the database.
   */
  public async addPolicy(_sec: string, ptype: string, rule: string[]) {
    const line = this.savePolicyLine(ptype, rule);
    await this.getCollection().insertOne(line);
  }

  /**
   * updatePolicy updates a policy rule in the database.
   */
  public async updatePolicy(
    _sec: string,
    ptype: string,
    oldRule: string[],
    newRule: string[],
  ) {
    const oldLine = this.deletePolicyLine(ptype, oldRule);
    const newLine = this.updatePolicyLine(ptype, newRule);
    const updateOperation = {
      $set: newLine,
      $unset: Object.keys(oldLine).reduce(
        (acc, key) => {
          if (
            !Object.prototype.hasOwnProperty.call(newLine, key) &&
            key !== 'createdAt' &&
            key !== 'updatedAt'
          ) {
            acc[key] = '';
          }
          return acc;
        },
        {} as Record<string, string>,
      ),
    };
    await this.getCollection().updateOne(oldLine, updateOperation);
  }

  /**
   * removePolicy removes a policy rule from the database.
   */
  public async removePolicy(_sec: string, ptype: string, rule: string[]) {
    const line = this.deletePolicyLine(ptype, rule);
    await this.getCollection().deleteOne(line);
  }

  /**
   * addPolicies adds many policies with rules to the database.
   */
  public async addPolicies(
    _sec: string,
    ptype: string,
    rules: string[][],
  ): Promise<void> {
    const lines = [];
    for (const r of rules) {
      lines.push(this.savePolicyLine(ptype, r));
    }
    await this.getCollection().insertMany(lines);
  }

  /**
   * removeFilteredPolicy removes many policy rules from the database.
   */
  public async removePolicies(
    _sec: string,
    ptype: string,
    rules: string[][],
  ): Promise<void> {
    const lines = [];
    for (const r of rules) {
      lines.push(this.deletePolicyLine(ptype, r));
    }

    const promises: Array<Promise<unknown>> = [];

    for (const line of lines) {
      promises.push(this.getCollection().deleteOne(line));
    }

    await Promise.all(promises);
  }

  /**
   * removeFilteredPolicy removes policy rules that match the filter from the database.
   */
  public async removeFilteredPolicy(
    _sec: string,
    ptype: string,
    fieldIndex: number,
    ...fieldValues: string[]
  ): Promise<void> {
    const line: CasbinRule = { ptype };

    for (let i = 0; i < 6; i++) {
      if (fieldIndex <= i && i < fieldIndex + fieldValues.length) {
        line[`v${i}` as keyof CasbinRule] = fieldValues[i - fieldIndex]!;
      }
    }

    await this.getCollection().deleteMany(line);
  }

  private async createCollection() {
    try {
      const db = this.getDatabase();
      const collectionExists = await db
        .listCollections({ name: this.collectionName })
        .hasNext();

      if (!collectionExists) {
        await db.createCollection(this.collectionName);
        this.logger.info(`Collection '${this.collectionName}' created`);
      }
    } catch (error) {
      throw this.wrapError(
        error,
        `Failed to create collection '${this.collectionName}'`,
      );
    }
  }

  private async createIndexes() {
    try {
      const collection = this.getCollection();
      const existingIndexes = await collection.listIndexes().toArray();

      const compoundIndexExists = existingIndexes.some(
        (index) => index.name === 'ptype_v0_v1_v2_v3_v4_v5_compound_index',
      );

      if (!compoundIndexExists) {
        await collection.createIndex(
          { ptype: 1, v0: 1, v1: 1, v2: 1, v3: 1, v4: 1, v5: 1 },
          { name: 'ptype_v0_v1_v2_v3_v4_v5_compound_index' },
        );
        this.logger.info('Compound index created for ptype and v0-v5');
      }

      const createdAtIndexExists = existingIndexes.some(
        (index) => index.key && index.key['createdAt'] === 1,
      );
      if (!createdAtIndexExists) {
        await collection.createIndex({ createdAt: 1 });
        this.logger.info('Index created for createdAt');
      }

      const updatedAtIndexExists = existingIndexes.some(
        (index) => index.key && index.key['updatedAt'] === 1,
      );
      if (!updatedAtIndexExists) {
        await collection.createIndex({ updatedAt: 1 });
        this.logger.info('Index created for updatedAt');
      }
    } catch (error) {
      this.logger.error('Failed to create database indexes:', { error });
    }
  }

  public async open() {
    try {
      await this.mongoClient.connect();
      await this.createCollection();
      await this.createIndexes();
    } catch (error) {
      throw this.wrapError(
        error,
        'Failed to open MongoDB connection and create collection',
      );
    }
  }

  private getCollection(): Collection {
    try {
      return this.mongoClient
        .db(this.databaseName)
        .collection(this.collectionName);
    } catch (error) {
      throw this.wrapError(
        error,
        `Failed to get collection '${this.collectionName}'`,
      );
    }
  }

  private getDatabase(): Db {
    try {
      return this.mongoClient.db(this.databaseName);
    } catch (error) {
      throw this.wrapError(
        error,
        `Failed to get database '${this.databaseName}'`,
      );
    }
  }

  private async clearCollection() {
    try {
      const list = await this.getDatabase()
        .listCollections({ name: this.collectionName })
        .toArray();

      if (list && list.length > 0) {
        if (this.dropCollectionOnManualSave) {
          await this.getCollection().drop();
          return;
        }
        await this.getCollection().deleteMany({});
      }
    } catch (error) {
      throw this.wrapError(
        error,
        `Failed to clear collection '${this.collectionName}'`,
      );
    }
  }

  private loadPolicyLine(line: CasbinRule, model: Model) {
    const result =
      line.ptype +
      ', ' +
      [line.v0, line.v1, line.v2, line.v3, line.v4, line.v5]
        .filter((n) => n)
        .join(', ');
    Helper.loadPolicyLine(result, model);
  }

  private convertRuleToDocument(
    ptype: string,
    rule: string[],
    timestampOption: 'none',
  ): CasbinRule;
  private convertRuleToDocument(
    ptype: string,
    rule: string[],
    timestampOption: 'updatedOnly',
  ): CasbinRuleWithUpdatedAt;
  private convertRuleToDocument(
    ptype: string,
    rule: string[],
    timestampOption: 'both',
  ): CasbinRuleWithTimestamps;
  private convertRuleToDocument(
    ptype: string,
    rule: string[],
    timestampOption: 'none' | 'updatedOnly' | 'both',
  ):
    | CasbinRule
    | (CasbinRule & { updatedAt: Date })
    | CasbinRuleWithTimestamps {
    const line: CasbinRule = { ptype };
    for (let i = 0; i < rule.length && i < 6; i++) {
      line[`v${i}` as keyof CasbinRule] = rule[i]!;
    }
    if (timestampOption === 'none') {
      return line;
    }
    const now = new Date();
    if (timestampOption === 'updatedOnly') {
      return { ...line, updatedAt: now };
    }
    return { ...line, createdAt: now, updatedAt: now };
  }

  private savePolicyLine(
    ptype: string,
    rule: string[],
  ): CasbinRuleWithTimestamps {
    return this.convertRuleToDocument(ptype, rule, 'both');
  }

  private deletePolicyLine(ptype: string, rule: string[]): CasbinRule {
    return this.convertRuleToDocument(ptype, rule, 'none');
  }

  private updatePolicyLine(ptype: string, rule: string[]) {
    return this.convertRuleToDocument(ptype, rule, 'updatedOnly');
  }

  private async getFilteredPolicyLines(filter?: Filter<unknown>) {
    const collection = this.getCollection();
    return this.useFilter
      ? collection.find(filter as Filter<unknown>).toArray()
      : collection.find().toArray();
  }

  private getAllPolicyRules(model: Model): CasbinRule[] {
    return [
      ...this.extractPolicyRules(model, 'p'),
      ...this.extractPolicyRules(model, 'g'),
    ];
  }

  private wrapError(error: unknown, context: string): MongoAdapterError {
    const message = error instanceof Error ? error.message : String(error);
    return new MongoAdapterError(`${context}: ${message}`, error);
  }
}
