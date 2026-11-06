function parse(text, log) {
  log.info('parse');
  try {
    return eval('(' + text + ')');
  } catch (error) {
    log.error('bad');
    return null;
  }
}
