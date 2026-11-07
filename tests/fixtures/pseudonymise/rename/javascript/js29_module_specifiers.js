import express from 'express';
import { Router } from "express/lib/router";
import ledger from './ledgerDb';
import core from 'kavach-core';
const viaRequire = require('express');
const local = require('../shared/accountLedger');
export { thing } from 'kavach-core';

const app = express();
app.use(viaRequire.json());
app.get('/accounts', (req, res) => res.json(ledger(core(local))));
