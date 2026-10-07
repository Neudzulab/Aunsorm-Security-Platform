import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from sasrl_recovery import ZeroSpectrum, zeta_model


class ModelContractTests(unittest.TestCase):
    def metadata(self):
        return {'source':'synthetic parser control, not a zero table',
                'complete_through':100,'ordinates':[],'l_function':zeta_model()}

    def load(self,data):
        return ZeroSpectrum.from_bytes(json.dumps(data).encode('utf-8'))

    def test_explicit_model_and_legacy_are_labelled_without_verification(self):
        data=self.metadata()
        explicit=self.load(data)
        self.assertEqual(explicit.model_declaration,'explicit_unverified_zeta_declaration')
        del data['l_function']
        self.assertEqual(self.load(data).model_declaration,'implicit_zeta_legacy_input')

    def test_contradictory_analytic_fields_are_rejected(self):
        alternatives={'id':'dirichlet_beta','degree':2,'conductor':4,'self_dual':False,
                      'normalization':'unitary_shift_by_half','critical_line_real_part':1.0,
                      'pole_at_one_order':0,'gamma_factor':'Gamma((s+1)/2)',
                      'trivial_zeros':'negative_odd_integers'}
        for key,value in alternatives.items():
            data=self.metadata()
            data['l_function'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.load(data)

    def test_boolean_numeric_equivalence_does_not_bypass_model(self):
        for key,value in [('degree',True),('conductor',1.0),('self_dual',1),
                          ('pole_at_one_order',True),('critical_line_real_part','0.5')]:
            data=self.metadata()
            data['l_function'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.load(data)

    def test_missing_extra_and_wrong_shape_model_fields_reject(self):
        for model in (None,[],{}, {**zeta_model(),'central_zero_order':1}):
            data=self.metadata()
            data['l_function']=model
            with self.assertRaises(ValueError):
                self.load(data)
        for key in zeta_model():
            data=self.metadata()
            del data['l_function'][key]
            with self.assertRaises(ValueError):
                self.load(data)

    def test_unknown_top_level_semantics_cannot_be_ignored(self):
        for key in ('family','conductor','negative_ordinates','normalization','self_dual'):
            data=self.metadata()
            data[key]='contradiction'
            with self.assertRaises(ValueError):
                self.load(data)

    def test_duplicate_nested_model_key_rejects(self):
        raw=json.dumps(self.metadata()).replace('"degree": 1','"degree": 1, "degree": 2')
        with self.assertRaises(ValueError):
            ZeroSpectrum.from_bytes(raw.encode('utf-8'))

    def test_cli_rejects_beta_model_before_writing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'input.json'
            target=Path(directory)/'output.json'
            data=self.metadata()
            data['l_function']['id']='dirichlet_beta'
            source.write_text(json.dumps(data),encoding='utf-8')
            run=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('sasrl_recovery.py')),
                                str(source),'--start','3','--stop','3','--output',str(target)],
                               capture_output=True,text=True)
            self.assertEqual(run.returncode,2)
            self.assertIn('zeta corrections cannot be reused',run.stderr)
            self.assertFalse(target.exists())

    def test_cli_labels_explicit_model_and_retains_unverified_status(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'input.json'
            target=Path(directory)/'output.json'
            data=json.loads((Path(__file__).with_name('data')/'sasrl-odlyzko-prefix.json').read_text(encoding='utf-8'))
            data['l_function']=zeta_model()
            source.write_text(json.dumps(data),encoding='utf-8')
            subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('sasrl_recovery.py')),
                            str(source),'--start','3','--stop','3','--output',str(target)],
                           capture_output=True,text=True,check=True)
            report=json.loads(target.read_text(encoding='utf-8'))
        self.assertEqual(report['l_function'],zeta_model())
        self.assertEqual(report['model_declaration'],'explicit_unverified_zeta_declaration')
        self.assertFalse(report['analytic_model_verified_from_input'])
        self.assertFalse(report['coverage_verified'])
        self.assertFalse(report['cryptographic_use'])


if __name__=='__main__':
    unittest.main()
