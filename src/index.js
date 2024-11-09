import {Hono} from 'hono';
import house from './household.js';
import ngo from './Ngo.js';
const app = new Hono();
app.route('/v1/household', house);
app.route('/v1/ngo', ngo);
export default app; 