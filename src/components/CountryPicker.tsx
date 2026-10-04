import { COUNTRIES, countryFlag, type Country } from '../data/countries';

const byName = [...COUNTRIES].sort((a, b) => a.name.localeCompare(b.name));

export function CountryPicker({
  value,
  onChange,
  showDialCode = false,
  label,
}: {
  value: string;
  onChange: (country: Country) => void;
  showDialCode?: boolean;
  label: string;
}) {
  return <label className="country-picker">{label}<select value={value} onChange={event => {
    const country = COUNTRIES.find(item => item.code === event.target.value);
    if (country) onChange(country);
  }} required>
    {byName.map(country => <option key={country.code} value={country.code}>
      {countryFlag(country.code)} {country.name}{showDialCode ? ` (${country.dialCode})` : ''}
    </option>)}
  </select></label>;
}
