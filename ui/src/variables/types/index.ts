export type FluxColumnType =
  | 'boolean'
  | 'unsignedLong'
  | 'long'
  | 'double'
  | 'string'
  | 'base64Binary'
  | 'dateTime'
  | 'duration'

export interface VariableValues {
  [variableID: string]: {
    values: string[]
    valueType: FluxColumnType
    selectedValue: string
  }
}

export interface ValueSelections {
  [variableID: string]: string
}
