interface Options {
  readonly retryLimit?: number;
  label?: string;
}

function configure(options: Options = {}): number {
  return options.retryLimit ?? 3;
}
